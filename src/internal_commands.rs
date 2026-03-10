//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::fmt::Write as _;

use chrono::prelude::*;
use indextree::NodeId;
use prettytable::{Table, format, row};
use similar::TextDiff;
use yang4::data::{
    Data, DataFormat, DataNodeRef, DataOperation, DataParserFlags,
    DataPrinterFlags, DataTree, DataValidationFlags,
};
use yang4::schema::SchemaNodeKind;

use crate::YANG_CTX;
use crate::error::CallbackError;
use crate::grpc::proto;
use crate::parser::ParsedArgs;
use crate::session::{CommandMode, ConfigurationType, Session};
use crate::token::{Commands, TokenKind};

const XPATH_PROTOCOL: &str =
    "/ietf-routing:routing/control-plane-protocols/control-plane-protocol";
const XPATH_RIB: &str = "/ietf-routing:routing/ribs/rib";

struct YangTableBuilder<'a> {
    session: &'a mut Session,
    data_type: proto::get_request::DataType,
    paths: Vec<(String, Vec<YangTableColumn>)>,
}

struct YangTableColumn {
    title: &'static str,
    value: YangTableValue,
}

enum YangTableValue {
    Leaf(&'static str, YangValueDisplayFormat),
    Fn(Box<dyn Fn(&DataNodeRef<'_>) -> String>),
}

enum YangValueDisplayFormat {
    Raw,
    Hex16,
    Hex32,
}

// ===== impl YangTableBuilder =====

impl<'a> YangTableBuilder<'a> {
    // Initializes the builder.
    pub fn new(
        session: &'a mut Session,
        data_type: proto::get_request::DataType,
    ) -> Self {
        Self {
            session,
            data_type,
            paths: Vec::new(),
        }
    }

    // Adds an XPath to the builder.
    pub fn xpath(mut self, xpath: &'a str) -> Self {
        self.paths.push((xpath.to_owned(), Vec::new()));
        self
    }

    // Adds a YANG list key filter to the last added XPath in the builder.
    pub fn filter_list_key<S>(mut self, key: &str, value: Option<S>) -> Self
    where
        S: AsRef<str>,
    {
        if let Some(value) = value
            && let Some((xpath, _)) = self.paths.last_mut()
        {
            *xpath = format!("{}[{}='{}']", xpath, key, value.as_ref());
        }
        self
    }

    // Adds a column to the last added XPath in the builder.
    pub fn column_leaf(
        mut self,
        title: &'static str,
        name: &'static str,
    ) -> Self {
        if let Some((_, columns)) = self.paths.last_mut() {
            columns.push(YangTableColumn {
                title,
                value: YangTableValue::Leaf(name, YangValueDisplayFormat::Raw),
            });
        }
        self
    }

    // Adds a column to the last added XPath in the builder.
    //
    // The column value is shown in hexadecimal, padded to a width of four
    // digits.
    pub fn column_leaf_hex16(
        mut self,
        title: &'static str,
        name: &'static str,
    ) -> Self {
        if let Some((_, columns)) = self.paths.last_mut() {
            columns.push(YangTableColumn {
                title,
                value: YangTableValue::Leaf(
                    name,
                    YangValueDisplayFormat::Hex16,
                ),
            });
        }
        self
    }

    // Adds a column to the last added XPath in the builder.
    //
    // The column value is shown in hexadecimal, padded to a width of eight
    // digits.
    pub fn column_leaf_hex32(
        mut self,
        title: &'static str,
        name: &'static str,
    ) -> Self {
        if let Some((_, columns)) = self.paths.last_mut() {
            columns.push(YangTableColumn {
                title,
                value: YangTableValue::Leaf(
                    name,
                    YangValueDisplayFormat::Hex32,
                ),
            });
        }
        self
    }

    pub fn column_from_fn(
        mut self,
        title: &'static str,
        cb: Box<dyn Fn(&DataNodeRef<'_>) -> String>,
    ) -> Self {
        if let Some((_, columns)) = self.paths.last_mut() {
            columns.push(YangTableColumn {
                title,
                value: YangTableValue::Fn(cb),
            });
        }
        self
    }

    // Recursively populates the table with data based on the specified paths
    // and columns.
    fn show_path(
        table: &mut Table,
        dnode: DataNodeRef<'_>,
        paths: &[(String, Vec<YangTableColumn>)],
        values: Vec<String>,
    ) {
        let Some((xpath, columns)) = paths.first() else {
            return;
        };

        for dnode in dnode.find_xpath(xpath).unwrap() {
            let mut values = values.clone();
            for column in columns {
                let value = match &column.value {
                    YangTableValue::Leaf(name, format) => {
                        let value = dnode.child_value(name);
                        match format {
                            YangValueDisplayFormat::Raw => value,
                            YangValueDisplayFormat::Hex16 => {
                                let value = value.parse::<u32>().unwrap();
                                format!("{:#06x}", value)
                            }
                            YangValueDisplayFormat::Hex32 => {
                                let value = value.parse::<u32>().unwrap();
                                format!("{:#010x}", value)
                            }
                        }
                    }
                    YangTableValue::Fn(cb) => (*cb)(&dnode),
                };
                values.push(value)
            }
            if paths.len() == 1 {
                table.add_row(values.into());
            } else {
                Self::show_path(table, dnode, &paths[1..], values);
            }
        }
    }

    // Builds and displays the table.
    pub fn show(self) -> Result<(), CallbackError> {
        let xpath_req = "/ietf-routing:routing/control-plane-protocols";

        // Fetch data.
        let data = fetch_data(self.session, self.data_type, xpath_req)?;
        let Some(dnode) = data.reference() else {
            return Ok(());
        };

        // Create the table.
        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
        let column_titles: Vec<_> = self
            .paths
            .iter()
            .flat_map(|(_, columns)| columns.iter())
            .map(|column| column.title)
            .collect();
        table.set_titles(column_titles.into());

        // Populate the table with data from the specified paths.
        let values = Vec::new();
        Self::show_path(&mut table, dnode, &self.paths, values);

        // Print the table.
        if !table.is_empty() {
            let writer = self.session.writer();
            table.print(writer)?;
            writeln!(writer)?;
        }

        Ok(())
    }
}

// ===== helper functions =====

fn get_arg(args: &mut ParsedArgs, name: &str) -> String {
    get_opt_arg(args, name).expect("Failed to find argument")
}

fn get_opt_arg(args: &mut ParsedArgs, name: &str) -> Option<String> {
    let found = args.iter().position(|(arg_name, _)| arg_name == name);
    if let Some(found) = found {
        return Some(args.remove(found).unwrap().1);
    }

    None
}

fn write_output(
    session: &mut Session,
    data: &str,
) -> Result<(), std::io::Error> {
    let w = session.writer();
    w.write_all(data.as_bytes())?;
    writeln!(w)?;
    Ok(())
}

fn fetch_data(
    session: &mut Session,
    data_type: proto::get_request::DataType,
    xpath: &str,
) -> Result<DataTree<'static>, String> {
    let yang_ctx = YANG_CTX.get().unwrap();
    let data_format = DataFormat::LYB;
    let data = session
        .get(data_type, data_format, true, Some(xpath.to_owned()))
        .map_err(|error| format!("% failed to fetch state data: {}", error))?;
    DataTree::parse_string(
        yang_ctx,
        data.as_bytes().unwrap(),
        data_format,
        DataParserFlags::NO_VALIDATION,
        DataValidationFlags::PRESENT,
    )
    .map_err(|error| format!("% failed to parse data: {}", error))
}

// ===== impl DataNodeRef =====

/// Extension methods for DataNodeRef.
pub trait DataNodeRefExt {
    fn child_value(&self, name: &str) -> String;
    fn child_opt_value(&self, name: &str) -> Option<String>;
    fn relative_value(&self, xpath: &str) -> String;
    fn relative_opt_value(&self, xpath: &str) -> Option<String>;
}

impl DataNodeRefExt for DataNodeRef<'_> {
    fn child_value(&self, name: &str) -> String {
        self.child_opt_value(name).unwrap_or("-".to_owned())
    }

    fn child_opt_value(&self, name: &str) -> Option<String> {
        self.children()
            .find(|dnode| dnode.schema().name() == name)
            .map(|dnode| dnode.value_canonical().unwrap())
    }

    fn relative_value(&self, xpath: &str) -> String {
        self.relative_opt_value(xpath).unwrap_or("-".to_owned())
    }

    fn relative_opt_value(&self, xpath: &str) -> Option<String> {
        self.find_xpath(xpath)
            .unwrap()
            .next()
            .map(|dnode| dnode.value_canonical().unwrap())
    }
}

// ===== "configure" =====

pub fn cmd_config(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let mode = CommandMode::Configure { nodes: vec![] };
    session.mode_set(mode);
    Ok(false)
}

// ===== "exit" =====

pub fn cmd_exit_exec(
    _commands: &Commands,
    _session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Do nothing.
    Ok(true)
}

pub fn cmd_exit_config(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    session.mode_config_exit();
    Ok(false)
}

// ===== "end" =====

pub fn cmd_end(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    session.mode_set(CommandMode::Operational);
    Ok(false)
}

// ===== "list" =====

pub fn cmd_list(
    commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    match session.mode() {
        CommandMode::Operational => {
            // List EXEC-level commands.
            cmd_list_root(commands, session, &commands.exec_root);
        }
        CommandMode::Configure { .. } => {
            // List internal configuration commands first.
            cmd_list_root(commands, session, &commands.config_dflt_internal);
            writeln!(session.writer(), "---")?;
            cmd_list_root(commands, session, &commands.config_root_internal);
            writeln!(session.writer(), "---")?;
            // List YANG configuration commands.
            let yang_root = session.mode().token(commands);
            cmd_list_root(commands, session, &yang_root);
        }
    }

    Ok(false)
}

pub fn cmd_list_root(
    commands: &Commands,
    session: &mut Session,
    top_token_id: &NodeId,
) {
    for token_id in
        top_token_id
            .descendants(&commands.arena)
            .skip(1)
            .filter(|token_id| {
                let token = commands.get_token(*token_id);
                token.action.is_some()
            })
    {
        let mut cmd_string = String::new();

        let ancestor_token_ids = token_id
            .ancestors(&commands.arena)
            .filter(|token_id| *token_id > *top_token_id)
            .collect::<Vec<NodeId>>();
        for ancestor_token_id in ancestor_token_ids.iter().rev() {
            let token = commands.get_token(*ancestor_token_id);
            if token.kind != TokenKind::Word {
                cmd_string.push_str(&token.name.to_uppercase());
            } else {
                cmd_string.push_str(&token.name);
            }
            cmd_string.push(' ');
        }

        let _ = writeln!(session.writer(), "{}", cmd_string);
    }
}

// ===== "pwd" =====

pub fn cmd_pwd(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    println!(
        "{}",
        session.mode().data_path().unwrap_or_else(|| "/".to_owned())
    );
    Ok(false)
}

// ===== "top" =====

pub fn cmd_top(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    session.mode_config_top();
    Ok(false)
}

// ===== "discard" =====

pub fn cmd_discard(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    session.candidate_discard();
    Ok(false)
}

// ===== "commit" =====

pub fn cmd_commit(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let comment = get_opt_arg(&mut args, "comment");
    match session.candidate_commit(comment) {
        Ok(_) => {
            println!("% configuration committed successfully");
        }
        Err(error) => {
            println!("% {}", error);
        }
    }

    Ok(false)
}

// ===== "validate" =====

pub fn cmd_validate(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    match session.candidate_validate() {
        Ok(_) => println!("% candidate configuration validated successfully"),
        Err(error) => {
            println!("% {}", error)
        }
    }

    Ok(false)
}

// ===== "show <candidate|running>" =====

fn cmd_show_config_cmds(
    config: &DataTree<'static>,
    with_defaults: bool,
) -> String {
    let mut output = String::new();

    // Iterate over data nodes that represent full commands.
    for dnode in config
        .traverse()
        .filter(|dnode| {
            let snode = dnode.schema();
            match snode.kind() {
                SchemaNodeKind::Container => !snode.is_np_container(),
                SchemaNodeKind::Leaf => !snode.is_list_key(),
                SchemaNodeKind::LeafList => true,
                SchemaNodeKind::List => true,
                _ => false,
            }
        })
        .filter(|dnode| with_defaults || !dnode.is_default())
    {
        let mut tokens = vec![];

        // Indentation.
        let mut indent = String::new();
        for _ in dnode
            .ancestors()
            .filter(|dnode| dnode.schema().kind() == SchemaNodeKind::List)
        {
            write!(indent, " ").unwrap();
        }

        // Build command line.
        for dnode in dnode
            .inclusive_ancestors()
            .take_while(|iter| {
                if *iter == dnode {
                    return true;
                }
                let snode = iter.schema();
                snode.kind() != SchemaNodeKind::List
            })
            .collect::<Vec<DataNodeRef<'_>>>()
            .iter()
            .rev()
        {
            tokens.push(dnode.schema().name().to_owned());
            for dnode in dnode.list_keys() {
                tokens.push(dnode.value_canonical().unwrap());
            }
            if let Some(value) = dnode.value_canonical() {
                tokens.push(value.clone());
            }
        }

        // Print command.
        if dnode.schema().kind() == SchemaNodeKind::List {
            writeln!(output, "{}!", indent).unwrap();
        }
        writeln!(output, "{}{}", indent, tokens.join(" ")).unwrap();
    }

    // Footer.
    writeln!(output, "!").unwrap();

    output
}

fn cmd_show_config_yang(
    config: &DataTree<'static>,
    format: DataFormat,
    with_defaults: bool,
) -> Result<String, String> {
    let mut flags = DataPrinterFlags::WITH_SIBLINGS;
    if with_defaults {
        flags |= DataPrinterFlags::WD_ALL;
    }

    let data = config
        .print_string(format, flags)
        .map_err(|error| format!("failed to print configuration: {}", error))?;
    Ok(data)
}

pub fn cmd_show_config(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Parse parameters.
    let config_type = get_arg(&mut args, "configuration");
    let config_type = match config_type.as_str() {
        "candidate" => ConfigurationType::Candidate,
        "running" => ConfigurationType::Running,
        _ => panic!("unexpected argument"),
    };
    let with_defaults = get_opt_arg(&mut args, "with-defaults").is_some();
    let format = get_opt_arg(&mut args, "format");

    // Get configuration.
    let config = session.get_configuration(config_type);

    // Display configuration.
    let data = match format.as_deref() {
        Some("json") => {
            cmd_show_config_yang(config, DataFormat::JSON, with_defaults)?
        }
        Some("xml") => {
            cmd_show_config_yang(config, DataFormat::XML, with_defaults)?
        }
        Some(_) => panic!("unknown format"),
        None => cmd_show_config_cmds(config, with_defaults),
    };
    write_output(session, &data)?;

    Ok(false)
}

pub fn cmd_show_config_changes(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let running = session.get_configuration(ConfigurationType::Running);
    let running = cmd_show_config_cmds(running, false);
    let candidate = session.get_configuration(ConfigurationType::Candidate);
    let candidate = cmd_show_config_cmds(candidate, false);

    let diff = TextDiff::from_lines(&running, &candidate);
    print!(
        "{}",
        diff.unified_diff()
            .context_radius(9)
            .header("running configuration", "candidate configuration")
    );

    Ok(false)
}

// ===== "show state" =====

pub fn cmd_show_state(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let xpath = get_opt_arg(&mut args, "xpath");
    let format = get_opt_arg(&mut args, "format");
    let format = match format.as_deref() {
        Some("json") => DataFormat::JSON,
        Some("xml") => DataFormat::XML,
        Some(_) => panic!("unknown format"),
        None => DataFormat::JSON,
    };

    match session.get(proto::get_request::DataType::State, format, false, xpath)
    {
        Ok(proto::data_tree::Data::DataString(data)) => {
            write_output(session, &data)?;
        }
        Ok(proto::data_tree::Data::DataBytes(_)) => unreachable!(),
        Err(error) => println!("% failed to fetch state data: {}", error),
    }

    Ok(false)
}

// ===== "show yang modules" =====

pub fn cmd_show_yang_modules(
    _commands: &Commands,
    _session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Create the table
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["Module", "Revision", "Flags", "Namespace"]);

    // Add a row per time
    let yang_ctx = YANG_CTX.get().unwrap();
    for module in yang_ctx.modules(false) {
        let mut flags = String::new();

        if module.is_implemented() {
            flags += "I";
        }

        table.add_row(row![
            module.name(),
            module.revision().unwrap_or("-"),
            flags,
            module.namespace()
        ]);
    }

    // Print the table to stdout
    println!(" Flags: I - Implemented");
    println!();
    table.printstd();
    println!();

    Ok(false)
}

// ===== IS-IS "show" commands =====

const PROTOCOL_ISIS: &str = "ietf-isis:isis";
const XPATH_ISIS_INTERFACE: &str = "ietf-isis:isis/interfaces/interface";
const XPATH_ISIS_ADJACENCY: &str = "adjacencies/adjacency";
const XPATH_ISIS_DATABASE: &str = "ietf-isis:isis/database/levels";
const XPATH_ISIS_LSP: &str = "lsp";
const XPATH_ISIS_ROUTE: &str = "ietf-isis:isis/local-rib/route";
const XPATH_ISIS_NEXTHOP: &str = "next-hops/next-hop";

pub fn cmd_show_isis_interface(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    YangTableBuilder::new(session, proto::get_request::DataType::All)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(PROTOCOL_ISIS))
        .column_leaf("Instance", "name")
        .xpath(XPATH_ISIS_INTERFACE)
        .filter_list_key("name", get_opt_arg(&mut args, "name"))
        .column_leaf("Name", "name")
        .column_leaf("Type", "interface-type")
        .column_leaf("Circuit ID", "circuit-id")
        .column_leaf("State", "state")
        .show()?;

    Ok(false)
}

pub fn cmd_show_isis_adjacency(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let hostnames = isis_hostnames(session)?;
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(PROTOCOL_ISIS))
        .column_leaf("Instance", "name")
        .xpath(XPATH_ISIS_INTERFACE)
        .filter_list_key("name", get_opt_arg(&mut args, "name"))
        .column_leaf("Interface", "name")
        .xpath(XPATH_ISIS_ADJACENCY)
        .column_from_fn(
            "System ID",
            Box::new(move |dnode| {
                let system_id = dnode.child_value("neighbor-sysid");
                hostnames.get(&system_id).cloned().unwrap_or(system_id)
            }),
        )
        .column_leaf("SNPA", "neighbor-snpa")
        .column_leaf("Level", "usage")
        .column_leaf("State", "state")
        .column_leaf("Holdtime", "hold-timer")
        .show()?;

    Ok(false)
}

pub fn cmd_show_isis_database(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let hostnames = isis_hostnames(session)?;
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(PROTOCOL_ISIS))
        .column_leaf("Instance", "name")
        .xpath(XPATH_ISIS_DATABASE)
        .column_leaf("Level", "level")
        .xpath(XPATH_ISIS_LSP)
        .column_from_fn(
            "LSP ID",
            Box::new(move |dnode| {
                let mut lsp_id = dnode.child_value("lsp-id");
                let system_id = &lsp_id[..14];
                if let Some(hostname) = hostnames.get(system_id) {
                    lsp_id.replace_range(..14, hostname);
                }
                lsp_id
            }),
        )
        .column_leaf_hex32("Sequence", "sequence")
        .column_leaf_hex16("Checksum", "checksum")
        .column_leaf("Lifetime", "remaining-lifetime")
        .show()?;

    Ok(false)
}

pub fn cmd_show_isis_route(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(PROTOCOL_ISIS))
        .column_leaf("Instance", "name")
        .xpath(XPATH_ISIS_ROUTE)
        .column_leaf("Prefix", "prefix")
        .column_leaf("Metric", "metric")
        .column_leaf("Level", "level")
        .xpath(XPATH_ISIS_NEXTHOP)
        .column_leaf("Nexthop Interface", "outgoing-interface")
        .column_leaf("Nexthop Address", "next-hop")
        .show()?;

    Ok(false)
}

fn isis_hostnames(
    session: &mut Session,
) -> Result<BTreeMap<String, String>, String> {
    let xpath = format!(
        "{}[type='{}'][name='{}']/ietf-isis:isis/hostnames",
        XPATH_PROTOCOL, PROTOCOL_ISIS, "main"
    );

    // Fetch hostname mappings.
    let data =
        fetch_data(session, proto::get_request::DataType::State, &xpath)?;

    // Collect hostname mappings into a binary tree.
    let hostnames = data
        .find_path(&xpath)
        .unwrap()
        .find_xpath("hostname")
        .unwrap()
        .filter_map(|dnode| {
            Some((
                dnode.child_opt_value("system-id")?,
                dnode.child_opt_value("hostname")?,
            ))
        })
        .collect();

    Ok(hostnames)
}

// ===== OSPF "show" commands =====

const PROTOCOL_OSPFV2: &str = "ietf-ospf:ospfv2";
const PROTOCOL_OSPFV3: &str = "ietf-ospf:ospfv3";
const XPATH_OSPF_AS_LSDB: &str =
    "database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/*/header";
const XPATH_OSPF_AREA: &str = "ietf-ospf:ospf/areas/area";
const XPATH_OSPF_AREA_LSDB: &str =
    "database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/*/header";
const XPATH_OSPF_INTERFACE: &str = "interfaces/interface";
const XPATH_OSPF_INTERFACE_LSDB: &str =
    "database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/*/header";
const XPATH_OSPF_VLINK: &str = "virtual-links/virtual-link";
const XPATH_OSPF_NEIGHBOR: &str = "neighbors/neighbor";
const XPATH_OSPF_RIB: &str = "ietf-ospf:ospf/local-rib/route";
const XPATH_OSPF_NEXTHOP: &str = "next-hops/next-hop";
const XPATH_OSPF_HOSTNAMES: &str =
    "ietf-ospf:ospf/holo-ospf:hostnames/hostname";

pub fn cmd_show_ospf_interface(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    YangTableBuilder::new(session, proto::get_request::DataType::All)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(XPATH_OSPF_AREA)
        .column_leaf("Area", "area-id")
        .xpath(XPATH_OSPF_INTERFACE)
        .filter_list_key("name", get_opt_arg(&mut args, "name"))
        .column_leaf("Name", "name")
        .column_leaf("Type", "interface-type")
        .column_leaf("State", "state")
        .column_leaf("Priority", "priority")
        .column_leaf("Cost", "cost")
        .column_from_fn(
            "Hello Interval (s)",
            Box::new(|dnode| {
                let interval = dnode.child_value("hello-interval");
                let remaining = dnode
                    .child_opt_value("hello-timer")
                    .map(|timer| format!("due in {}", timer))
                    .unwrap_or("inactive".to_owned());
                format!("{} ({})", interval, remaining)
            }),
        )
        .show()?;

    Ok(false)
}

pub fn cmd_show_ospf_interface_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Parse arguments.
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let name = get_opt_arg(&mut args, "name");

    // Fetch data.
    let xpath_req = "/ietf-routing:routing/control-plane-protocols";
    let xpath_instance = format!(
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}']",
        protocol
    );
    let xpath_area = "ietf-ospf:ospf/areas/area";
    let mut xpath_iface = "interfaces/interface".to_owned();
    if let Some(name) = &name {
        xpath_iface = format!("{}[name='{}']", xpath_iface, name);
    }
    let data =
        fetch_data(session, proto::get_request::DataType::All, xpath_req)?;

    // Iterate over OSPF instances.
    for dnode in data.find_xpath(&xpath_instance).unwrap() {
        let instance = dnode.child_value("name");

        // Iterate over OSPF areas.
        for dnode in dnode.find_xpath(xpath_area).unwrap() {
            let area = dnode.child_value("area-id");

            // Iterate over OSPF interfaces.
            let output = session.writer();
            for dnode in dnode.find_xpath(&xpath_iface).unwrap() {
                writeln!(output, "{}", dnode.child_value("name")).unwrap();
                writeln!(output, " instance: {}", instance).unwrap();
                writeln!(output, " area: {}", area).unwrap();
                for dnode in dnode
                    .children()
                    .filter(|dnode| !dnode.schema().is_list_key())
                {
                    let snode = dnode.schema();
                    let snode_name = snode.name();
                    if let Some(value) = dnode.value_canonical() {
                        writeln!(output, " {}: {}", snode_name, value).unwrap();
                    } else if snode_name == "statistics" {
                        writeln!(output, " statistics").unwrap();
                        for dnode in dnode.children() {
                            let snode = dnode.schema();
                            let snode_name = snode.name();
                            if let Some(value) = dnode.value_canonical() {
                                writeln!(output, "  {}: {}", snode_name, value)
                                    .unwrap();
                            }
                        }
                    }
                }
                writeln!(output).unwrap();
            }
        }
    }

    Ok(false)
}

pub fn cmd_show_ospf_vlink(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let hostnames = ospf_hostnames(session, protocol)?;
    YangTableBuilder::new(session, proto::get_request::DataType::All)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(XPATH_OSPF_AREA)
        .xpath(XPATH_OSPF_VLINK)
        .column_leaf("Transit Area", "transit-area-id")
        .xpath(XPATH_OSPF_NEIGHBOR)
        .column_from_fn(
            "Router ID",
            Box::new(move |dnode| {
                let router_id = dnode.child_value("neighbor-router-id");
                hostnames.get(&router_id).cloned().unwrap_or(router_id)
            }),
        )
        .column_leaf("Address", "address")
        .column_leaf("State", "state")
        .column_from_fn(
            "Dead Interval (s)",
            Box::new(|dnode| {
                let interval = dnode.relative_value("../../dead-interval");
                let remaining = dnode.child_value("dead-timer");
                format!("{} ({})", interval, remaining)
            }),
        )
        .show()?;

    Ok(false)
}

pub fn cmd_show_ospf_neighbor(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let hostnames = ospf_hostnames(session, protocol)?;
    YangTableBuilder::new(session, proto::get_request::DataType::All)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(XPATH_OSPF_AREA)
        .column_leaf("Area", "area-id")
        .xpath(XPATH_OSPF_INTERFACE)
        .column_leaf("Interface", "name")
        .xpath(XPATH_OSPF_NEIGHBOR)
        .filter_list_key(
            "neighbor-router-id",
            get_opt_arg(&mut args, "router_id"),
        )
        .column_from_fn(
            "Router ID",
            Box::new(move |dnode| {
                let router_id = dnode.child_value("neighbor-router-id");
                hostnames.get(&router_id).cloned().unwrap_or(router_id)
            }),
        )
        .column_leaf("Address", "address")
        .column_leaf("State", "state")
        .column_from_fn(
            "Dead Interval (s)",
            Box::new(|dnode| {
                let interval = dnode.relative_value("../../dead-interval");
                let remaining = dnode.child_value("dead-timer");
                format!("{} ({})", interval, remaining)
            }),
        )
        .show()?;

    Ok(false)
}

pub fn cmd_show_ospf_neighbor_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Parse arguments.
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let router_id = get_opt_arg(&mut args, "router_id");

    // Fetch data.
    let xpath_req = "/ietf-routing:routing/control-plane-protocols";
    let xpath_instance = format!(
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}']",
        protocol
    );
    let xpath_area = "ietf-ospf:ospf/areas/area";
    let xpath_iface = "interfaces/interface";
    let mut xpath_nbr = "neighbors/neighbor".to_owned();
    if let Some(router_id) = &router_id {
        xpath_nbr =
            format!("{}[neighbor-router-id='{}']", xpath_nbr, router_id);
    }
    let data =
        fetch_data(session, proto::get_request::DataType::All, xpath_req)?;

    // Iterate over OSPF instances.
    let output = session.writer();
    for dnode in data.find_xpath(&xpath_instance).unwrap() {
        let instance = dnode.child_value("name");

        // Iterate over OSPF areas.
        for dnode in dnode.find_xpath(xpath_area).unwrap() {
            let area = dnode.child_value("area-id");

            // Iterate over OSPF interfaces.
            for dnode in dnode.find_xpath(xpath_iface).unwrap() {
                let ifname = dnode.child_value("name");

                // Iterate over OSPF neighbors.
                for dnode in dnode.find_xpath(&xpath_nbr).unwrap() {
                    writeln!(
                        output,
                        "{}",
                        dnode.child_value("neighbor-router-id")
                    )
                    .unwrap();
                    writeln!(output, " instance: {}", instance).unwrap();
                    writeln!(output, " area: {}", area).unwrap();
                    writeln!(output, " interface: {}", ifname).unwrap();
                    for dnode in dnode
                        .children()
                        .filter(|dnode| !dnode.schema().is_list_key())
                    {
                        let snode = dnode.schema();
                        let snode_name = snode.name();
                        if let Some(value) = dnode.value_canonical() {
                            writeln!(output, " {}: {}", snode_name, value)
                                .unwrap();
                        } else if snode_name == "statistics"
                            || snode_name == "graceful-restart"
                        {
                            writeln!(output, " statistics").unwrap();
                            for dnode in dnode.children() {
                                let snode = dnode.schema();
                                let snode_name = snode.name();
                                if let Some(value) = dnode.value_canonical() {
                                    writeln!(
                                        output,
                                        "  {}: {}",
                                        snode_name, value
                                    )
                                    .unwrap();
                                }
                            }
                        }
                    }
                    writeln!(output).unwrap();
                }
            }
        }
    }

    Ok(false)
}

pub fn cmd_show_ospf_database_as(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let hostnames = ospf_hostnames(session, protocol)?;
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(XPATH_OSPF_AS_LSDB)
        .column_from_fn(
            "Type",
            Box::new(move |dnode| {
                let lsa_type = dnode.child_value("type");
                if lsa_type.contains("opaque-lsa") {
                    "opaque-lsa".to_owned()
                } else {
                    lsa_type[17..].to_owned()
                }
            }),
        )
        .column_leaf("LSA ID", "lsa-id")
        .column_from_fn(
            "Adv Router",
            Box::new(move |dnode| {
                let router_id = dnode.child_value("adv-router");
                hostnames.get(&router_id).cloned().unwrap_or(router_id)
            }),
        )
        .column_leaf("Age", "age")
        .column_leaf_hex32("Sequence", "seq-num")
        .column_leaf("Checksum", "checksum")
        .show()?;

    Ok(false)
}

pub fn cmd_show_ospf_database_area(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let hostnames = ospf_hostnames(session, protocol)?;
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(XPATH_OSPF_AREA)
        .column_leaf("Area", "area-id")
        .xpath(XPATH_OSPF_AREA_LSDB)
        .column_from_fn(
            "Type",
            Box::new(move |dnode| {
                let lsa_type = dnode.child_value("type");
                if lsa_type.contains("opaque-lsa") {
                    "opaque-lsa".to_owned()
                } else {
                    lsa_type[17..].to_owned()
                }
            }),
        )
        .column_leaf("LSA ID", "lsa-id")
        .column_from_fn(
            "Adv Router",
            Box::new(move |dnode| {
                let router_id = dnode.child_value("adv-router");
                hostnames.get(&router_id).cloned().unwrap_or(router_id)
            }),
        )
        .column_leaf("Age", "age")
        .column_leaf_hex32("Sequence", "seq-num")
        .column_leaf("Checksum", "checksum")
        .show()?;

    Ok(false)
}

pub fn cmd_show_ospf_database_link(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let hostnames = ospf_hostnames(session, protocol)?;
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(XPATH_OSPF_AREA)
        .column_leaf("Area", "area-id")
        .xpath(XPATH_OSPF_INTERFACE)
        .column_leaf("Interface", "name")
        .xpath(XPATH_OSPF_INTERFACE_LSDB)
        .column_from_fn(
            "Type",
            Box::new(move |dnode| {
                let lsa_type = dnode.child_value("type");
                if lsa_type.contains("opaque-lsa") {
                    "opaque-lsa".to_owned()
                } else {
                    lsa_type[17..].to_owned()
                }
            }),
        )
        .column_leaf("LSA ID", "lsa-id")
        .column_from_fn(
            "Adv Router",
            Box::new(move |dnode| {
                let router_id = dnode.child_value("adv-router");
                hostnames.get(&router_id).cloned().unwrap_or(router_id)
            }),
        )
        .column_leaf("Age", "age")
        .column_leaf_hex32("Sequence", "seq-num")
        .column_leaf("Checksum", "checksum")
        .show()?;

    Ok(false)
}

pub fn cmd_show_ospf_route(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(XPATH_OSPF_RIB)
        .filter_list_key("prefix", get_opt_arg(&mut args, "prefix"))
        .column_leaf("Prefix", "prefix")
        .column_leaf("Metric", "metric")
        .column_leaf("Type", "route-type")
        .column_leaf("Tag", "route-tag")
        .xpath(XPATH_OSPF_NEXTHOP)
        .column_leaf("Nexthop Interface", "outgoing-interface")
        .column_leaf("Nexthop Address", "next-hop")
        .show()?;

    Ok(false)
}

pub fn cmd_show_ospf_hostnames(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };

    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(XPATH_OSPF_HOSTNAMES)
        .column_leaf("Router ID", "router-id")
        .column_leaf("Hostname", "hostname")
        .show()?;

    Ok(false)
}

fn ospf_hostnames(
    session: &mut Session,
    protocol: &str,
) -> Result<BTreeMap<String, String>, String> {
    let xpath = format!(
        "{}[type='{}'][name='{}']/ietf-ospf:ospf/holo-ospf:hostnames",
        XPATH_PROTOCOL, protocol, "main"
    );

    // Fetch hostname mappings.
    let data =
        fetch_data(session, proto::get_request::DataType::State, &xpath)?;

    // Collect hostname mappings into a binary tree.
    let hostnames = data
        .find_path(&xpath)
        .unwrap()
        .find_xpath("hostname")
        .unwrap()
        .filter_map(|dnode| {
            Some((
                dnode.child_opt_value("router-id")?,
                dnode.child_opt_value("hostname")?,
            ))
        })
        .collect();

    Ok(hostnames)
}

// ===== RIP "show" commands =====

const PROTOCOL_RIPV2: &str = "ietf-rip:ripv2";
const PROTOCOL_RIPNG: &str = "ietf-rip:ripng";
const XPATH_RIP_INTERFACE: &str = "ietf-rip:rip/interfaces/interface";
const AFI4: &str = "ipv4";
const AFI6: &str = "ipv6";

pub fn cmd_show_rip_interface(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Parse arguments.
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ripv2" => PROTOCOL_RIPV2,
        "ripng" => PROTOCOL_RIPNG,
        _ => unreachable!(),
    };
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(XPATH_RIP_INTERFACE)
        .filter_list_key("interface", get_opt_arg(&mut args, "name"))
        .column_leaf("Name", "interface")
        .column_leaf("State", "oper-status")
        .show()?;

    Ok(false)
}

pub fn cmd_show_rip_interface_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Parse arguments.
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ripv2" => PROTOCOL_RIPV2,
        "ripng" => PROTOCOL_RIPNG,
        _ => unreachable!(),
    };

    let name = get_opt_arg(&mut args, "name");

    // Fetch data.
    let xpath_req = "/ietf-routing:routing/control-plane-protocols";
    let xpath_instance = format!(
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}']",
        protocol
    );

    let mut xpath_iface = "ietf-rip:rip/interfaces/interface".to_owned();

    if let Some(name) = &name {
        // xpath_iface = format!("{}[name='{}']", xpath_iface, name);
        xpath_iface = format!("{}[interface='{}']", xpath_iface, name);
    }

    let data =
        fetch_data(session, proto::get_request::DataType::State, xpath_req)?;

    // Iterate over RIP instances.
    let output = session.writer();
    for dnode in data.find_xpath(&xpath_instance).unwrap() {
        let instance = dnode.child_value("name");

        // Iterate over RIP interfaces.
        for dnode in dnode.find_xpath(&xpath_iface).unwrap() {
            // "interface" keyword is used to identify interface name
            writeln!(output, "{}", dnode.child_value("interface")).unwrap();
            writeln!(output, " instance: {}", instance).unwrap();
            for dnode in dnode
                .children()
                .filter(|dnode| !dnode.schema().is_list_key())
            {
                let snode = dnode.schema();
                let snode_name = snode.name();
                if let Some(value) = dnode.value_canonical() {
                    writeln!(output, " {}: {}", snode_name, value).unwrap();
                } else if snode_name == "statistics" {
                    writeln!(output, " statistics").unwrap();
                    for dnode in dnode.children() {
                        let snode = dnode.schema();
                        let snode_name = snode.name();
                        if let Some(value) = dnode.value_canonical() {
                            writeln!(output, "  {}: {}", snode_name, value)
                                .unwrap();
                        }
                    }
                }
            }
            writeln!(output).unwrap();
        }
    }

    Ok(false)
}

pub fn cmd_show_rip_neighbor(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Parse arguments.
    let (protocol, afi, address) = match get_arg(&mut args, "protocol").as_str()
    {
        "ripv2" => (PROTOCOL_RIPV2, AFI4, "ipv4-address"),
        "ripng" => (PROTOCOL_RIPNG, AFI6, "ipv6-address"),
        _ => unreachable!(),
    };

    let xpath_rip_neighbor = format!("ietf-rip:rip/{}/neighbors/neighbor", afi);

    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(xpath_rip_neighbor.as_str())
        .filter_list_key(address, get_opt_arg(&mut args, "address"))
        .column_leaf("Address", address)
        .column_leaf("Last update", "last-update")
        .show()?;

    Ok(false)
}

pub fn cmd_show_rip_neighbor_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Parse arguments.
    let (protocol, afi, address) = match get_arg(&mut args, "protocol").as_str()
    {
        "ripv2" => (PROTOCOL_RIPV2, "ipv4", "ipv4-address"),
        "ripng" => (PROTOCOL_RIPNG, "ipv6", "ipv6-address"),
        _ => unreachable!(),
    };

    let nb_address = get_opt_arg(&mut args, "address");

    // Fetch data.
    let xpath_req = "/ietf-routing:routing/control-plane-protocols";
    let xpath_instance = format!(
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}']",
        protocol
    );

    let mut xpath_neighbor = format!("ietf-rip:rip/{}/neighbors/neighbor", afi);

    if let Some(nb_address) = &nb_address {
        xpath_neighbor =
            format!("{}[{}='{}']", xpath_neighbor, address, nb_address);
    }

    let data =
        fetch_data(session, proto::get_request::DataType::State, xpath_req)?;

    // Iterate over RIP instances.
    let output = session.writer();
    for dnode in data.find_xpath(&xpath_instance).unwrap() {
        let instance = dnode.child_value("name");

        // Iterate over RIP neighbors.
        for dnode in dnode.find_xpath(&xpath_neighbor).unwrap() {
            // "address" keyword is used to identify the afi address type
            writeln!(output, "{}", dnode.child_value(address)).unwrap();
            writeln!(output, " instance: {}", instance).unwrap();
            for dnode in dnode
                .children()
                .filter(|dnode| !dnode.schema().is_list_key())
            {
                let snode = dnode.schema();
                let snode_name = snode.name();
                if let Some(value) = dnode.value_canonical() {
                    writeln!(output, " {}: {}", snode_name, value).unwrap();
                }
            }
            writeln!(output).unwrap();
        }
    }

    Ok(false)
}

pub fn cmd_show_rip_route(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Parse arguments.
    let (protocol, afi, prefix) = match get_arg(&mut args, "protocol").as_str()
    {
        "ripv2" => (PROTOCOL_RIPV2, AFI4, "ipv4-prefix"),
        "ripng" => (PROTOCOL_RIPNG, AFI6, "ipv6-prefix"),
        _ => unreachable!(),
    };

    let xpath_rip_rib = format!("ietf-rip:rip/{}/routes/route", afi);

    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(&xpath_rip_rib)
        .filter_list_key(prefix, get_opt_arg(&mut args, "prefix"))
        .column_leaf("Prefix", prefix)
        .column_leaf("Metric", "metric")
        .column_leaf("Type", "route-type")
        .column_leaf("Tag", "route-tag")
        .column_leaf("Nexthop Interface", "interface")
        .column_leaf("Nexthop Address", "next-hop")
        .show()?;

    Ok(false)
}

// ===== LDP "show" commands =====

const PROTOCOL_MPLS_LDP: &str = "ietf-mpls-ldp:mpls-ldp";
const XPATH_MPLS_LDP_INTERFACE: &str =
    "ietf-mpls-ldp:mpls-ldp/discovery/interfaces/interface";

const XPATH_MPLS_LDP_ADJACENCY: &str =
    "address-families/ipv4/hello-adjacencies/hello-adjacency";
const XPATH_MPLS_LDP_ADJACENCY_PEER: &str = "peer";
const XPATH_MPLS_LDP_PEER: &str = "ietf-mpls-ldp:mpls-ldp/peers/peer";
const XPATH_MPLS_LDP_BINDING_ADDRESS: &str =
    "ietf-mpls-ldp:mpls-ldp/global/address-families/ipv4/bindings/address";
const XPATH_MPLS_LDP_BINDING_FEC: &str =
    "ietf-mpls-ldp:mpls-ldp/global/address-families/ipv4/bindings/fec-label";
const XPATH_MPLS_LDP_BINDING_FEC_PEER: &str = "peer";

pub fn cmd_show_mpls_ldp_discovery(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(PROTOCOL_MPLS_LDP))
        .column_leaf("Instance", "name")
        .xpath(XPATH_MPLS_LDP_INTERFACE)
        .filter_list_key("name", get_opt_arg(&mut args, "name"))
        .column_leaf("Name", "name")
        .xpath(XPATH_MPLS_LDP_ADJACENCY)
        .column_leaf("Adjacent Address", "adjacent-address")
        .xpath(XPATH_MPLS_LDP_ADJACENCY_PEER)
        .column_leaf("LSR Id", "lsr-id")
        .show()?;

    Ok(false)
}

pub fn cmd_show_mpls_ldp_discovery_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Parse arguments.
    let name = get_opt_arg(&mut args, "name");

    // Fetch data.
    let xpath_req = "/ietf-routing:routing/control-plane-protocols";
    let xpath_instance = format!(
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}']",
        PROTOCOL_MPLS_LDP
    );

    let mut xpath_iface =
        "ietf-mpls-ldp:mpls-ldp/discovery/interfaces/interface".to_owned();
    if let Some(name) = &name {
        xpath_iface = format!("{}[name='{}']", xpath_iface, name);
    }

    // when find_xpath is invoked current node is address-families
    let xpath_adjacency = "ipv4/hello-adjacencies/hello-adjacency".to_owned();

    let data =
        fetch_data(session, proto::get_request::DataType::State, xpath_req)?;

    // Iterate over MPLS LDP instances.
    let output = session.writer();
    for dnode in data.find_xpath(&xpath_instance).unwrap() {
        let instance = dnode.child_value("name");

        // Iterate over MPLS LDP interfaces.
        for dnode in dnode.find_xpath(&xpath_iface).unwrap() {
            writeln!(output, "{}", dnode.child_value("name")).unwrap();
            writeln!(output, " instance: {}", instance).unwrap();
            for dnode in dnode
                .children()
                .filter(|dnode| !dnode.schema().is_list_key())
            {
                let snode = dnode.schema();
                let snode_name = snode.name();
                if let Some(value) = dnode.value_canonical() {
                    writeln!(output, " {}: {}", snode_name, value).unwrap();
                } else if snode_name == "address-families" {
                    writeln!(output, "  {}:", snode_name).unwrap();
                    writeln!(output, "   address-family:").unwrap();
                    writeln!(output, "    ipv4:").unwrap();
                    writeln!(output, "     hello-adjacencies:").unwrap();
                    writeln!(output, "      hello-adjacency:").unwrap();
                    for dnode in dnode.find_xpath(&xpath_adjacency).unwrap() {
                        for dnode in dnode.children() {
                            let snode = dnode.schema();
                            let snode_name = snode.name();
                            if let Some(value) = dnode.value_canonical() {
                                writeln!(
                                    output,
                                    "       {}: {}",
                                    snode_name, value
                                )
                                .unwrap();
                            } else {
                                writeln!(output, "       {}:", snode_name)
                                    .unwrap();
                                for dnode in dnode.children() {
                                    let snode = dnode.schema();
                                    let snode_name = snode.name();
                                    if let Some(value) = dnode.value_canonical()
                                    {
                                        writeln!(
                                            output,
                                            "        {}: {}",
                                            snode_name, value
                                        )
                                        .unwrap();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            writeln!(output).unwrap();
        }
    }

    Ok(false)
}

pub fn cmd_show_mpls_ldp_peer(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(PROTOCOL_MPLS_LDP))
        .column_leaf("Instance", "name")
        .xpath(XPATH_MPLS_LDP_PEER)
        .filter_list_key("lsr-id", get_opt_arg(&mut args, "lsr-id"))
        .column_leaf("Peer", "lsr-id")
        .column_leaf("State", "session-state")
        .column_leaf("Uptime", "up-time")
        .xpath(XPATH_MPLS_LDP_ADJACENCY)
        .column_leaf("Local address", "local-address")
        .column_leaf("Adjacent address", "adjacent-address")
        .show()?;

    Ok(false)
}

pub fn cmd_show_mpls_ldp_peer_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    // Parse arguments.
    let lsr_id = get_opt_arg(&mut args, "lsr-id");

    // Fetch data.
    let xpath_req = "/ietf-routing:routing/control-plane-protocols";
    let xpath_instance = format!(
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}']",
        PROTOCOL_MPLS_LDP
    );

    let mut xpath_peer = "ietf-mpls-ldp:mpls-ldp/peers/peer".to_owned();
    if let Some(lsr_id) = &lsr_id {
        xpath_peer = format!("{}[lsr-id='{}']", xpath_peer, lsr_id);
    }

    let xpath_adjacency = "ipv4/hello-adjacencies/hello-adjacency".to_owned();

    let xpath_capability = "capability".to_owned();

    let data =
        fetch_data(session, proto::get_request::DataType::State, xpath_req)?;

    // Iterate over MPLS LDP instances.
    let output = session.writer();
    for dnode in data.find_xpath(&xpath_instance).unwrap() {
        let instance = dnode.child_value("name");

        // Iterate over MPLS LDP peers.
        for dnode in dnode.find_xpath(&xpath_peer).unwrap() {
            writeln!(output, "{}", dnode.child_value("lsr-id")).unwrap();
            writeln!(output, " instance: {}", instance).unwrap();
            for dnode in dnode
                .children()
                .filter(|dnode| !dnode.schema().is_list_key())
            {
                let snode = dnode.schema();
                let snode_name = snode.name();
                if let Some(value) = dnode.value_canonical() {
                    writeln!(output, " {}: {}", snode_name, value).unwrap();
                } else if snode_name == "address-families" {
                    writeln!(output, "  {}:", snode_name).unwrap();
                    writeln!(output, "   address-family:").unwrap();
                    writeln!(output, "    ipv4:").unwrap();
                    writeln!(output, "     hello-adjacencies:").unwrap();
                    writeln!(output, "      hello-adjacency:").unwrap();
                    for dnode in dnode.find_xpath(&xpath_adjacency).unwrap() {
                        for dnode in dnode.children() {
                            let snode = dnode.schema();
                            let snode_name = snode.name();
                            if let Some(value) = dnode.value_canonical() {
                                writeln!(
                                    output,
                                    "       {}: {}",
                                    snode_name, value
                                )
                                .unwrap();
                            } else {
                                writeln!(output, "       {}:", snode_name)
                                    .unwrap();
                                for dnode in dnode.children() {
                                    let snode = dnode.schema();
                                    let snode_name = snode.name();
                                    if let Some(value) = dnode.value_canonical()
                                    {
                                        writeln!(
                                            output,
                                            "        {}: {}",
                                            snode_name, value
                                        )
                                        .unwrap();
                                    }
                                }
                            }
                        }
                    }
                } else if snode_name == "received-peer-state" {
                    writeln!(output, "  {}:", snode_name).unwrap();
                    writeln!(output, "   capability:").unwrap();
                    for dnode in dnode.find_xpath(&xpath_capability).unwrap() {
                        for dnode in dnode.children() {
                            let snode = dnode.schema();
                            let snode_name = snode.name();
                            if let Some(value) = dnode.value_canonical() {
                                writeln!(
                                    output,
                                    "    {}: {}",
                                    snode_name, value
                                )
                                .unwrap();
                            } else {
                                writeln!(output, "    {}:", snode_name)
                                    .unwrap();
                                for dnode in dnode.children() {
                                    let snode = dnode.schema();
                                    let snode_name = snode.name();
                                    if let Some(value) = dnode.value_canonical()
                                    {
                                        writeln!(
                                            output,
                                            "     {}: {}",
                                            snode_name, value
                                        )
                                        .unwrap();
                                    }
                                }
                            }
                        }
                    }
                } else if snode_name == "label-advertisement-mode"
                    || snode_name == "session-holdtime"
                    || snode_name == "tcp-connection"
                    || snode_name == "statistics"
                {
                    writeln!(output, "  {}:", snode_name).unwrap();
                    for dnode in dnode.children() {
                        let snode = dnode.schema();
                        let snode_name = snode.name();
                        if let Some(value) = dnode.value_canonical() {
                            writeln!(output, "   {}: {}", snode_name, value)
                                .unwrap();
                        } else {
                            writeln!(output, "   {}:", snode_name).unwrap();
                            for dnode in dnode.children() {
                                let snode = dnode.schema();
                                let snode_name = snode.name();
                                if let Some(value) = dnode.value_canonical() {
                                    writeln!(
                                        output,
                                        "    {}: {}",
                                        snode_name, value
                                    )
                                    .unwrap();
                                }
                            }
                        }
                    }
                }
            }
            writeln!(output).unwrap();
        }
    }

    Ok(false)
}

pub fn cmd_show_mpls_ldp_binding_address(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(PROTOCOL_MPLS_LDP))
        .column_leaf("Instance", "name")
        .xpath(XPATH_MPLS_LDP_BINDING_ADDRESS)
        .filter_list_key("address", get_opt_arg(&mut args, "address"))
        .column_leaf("Address", "address")
        .column_leaf("Advertisement type", "advertisement-type")
        .column_from_fn(
            "Nexthop",
            Box::new(|dnode| {
                let mut output = String::new();
                if dnode.child_value("advertisement-type") == "advertised" {
                    output = "-".to_string();
                } else {
                    for dnode in dnode.children() {
                        let nh = dnode.child_value("lsr-id");
                        let lsi = dnode.child_value("label-space-id");
                        output = format!("{}:{}", nh, lsi)
                    }
                }
                output
            }),
        )
        .show()?;

    Ok(false)
}

pub fn cmd_show_mpls_ldp_binding_fec(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    YangTableBuilder::new(session, proto::get_request::DataType::State)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(PROTOCOL_MPLS_LDP))
        .column_leaf("Instance", "name")
        .xpath(XPATH_MPLS_LDP_BINDING_FEC)
        .filter_list_key("fec", get_opt_arg(&mut args, "fec"))
        .column_leaf("Prefix", "fec")
        .xpath(XPATH_MPLS_LDP_BINDING_FEC_PEER)
        .filter_list_key("lsr-id", get_opt_arg(&mut args, "lsr-id"))
        .column_from_fn(
            "Nexthop",
            Box::new(|dnode| {
                let lsr_id = dnode.child_value("lsr-id");
                let label_space_id = dnode.child_value("label-space-id");
                format!("{}:{}", lsr_id, label_space_id)
            }),
        )
        .column_leaf("Advertisement type", "advertisement-type")
        .column_from_fn(
            "Label",
            Box::new(|dnode| {
                let lsr_id = dnode.child_value("label");
                match lsr_id.as_str() {
                    "ietf-routing-types:implicit-null-label" => {
                        "imp-null".to_owned()
                    }
                    "ietf-routing-types:explicit-null-label" => {
                        "exp-null".to_owned()
                    }
                    _ => lsr_id,
                }
            }),
        )
        .column_leaf("In use", "used-in-forwarding")
        .show()?;

    Ok(false)
}

// ===== BGP "show" commands =====
const PROTOCOL_BGP: &str = "ietf-bgp:bgp";
const XPATH_BGP_NEIGHBOR: &str = "ietf-bgp:bgp/neighbors/neighbor";
const XPATH_BGP_NEIGHBOR_STATS: &str = "statistics";
const XPATH_BGP_NEIGHBOR_STATS_MSGS: &str = "messages";
const XPATH_BGP_RIB_AFI_SAFI: &str = "ietf-bgp:bgp/rib/afi-safis/afi-safi";
const XPATH_BGP_RIB_ATTR_SET: &str = "ietf-bgp:bgp/rib/attr-sets";

fn uptime_from_secs(secs: i64) -> String {
    let days = secs / 86400;
    let day_secs = secs % 86400;
    let hours = day_secs / 3600;
    let minutes = day_secs % 3600 / 60;
    let seconds = day_secs % 60;

    format!(
        "{}{:02}:{:02}:{:02}",
        if days > 0 {
            format!("{}d ", days)
        } else {
            "".to_string()
        },
        hours,
        minutes,
        seconds
    )
}

pub fn cmd_show_bgp_summary(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let afi = get_opt_arg(&mut args, "afi").unwrap_or("ipv4".to_owned());

    let afi = match afi.as_str() {
        "ipv4" => "iana-bgp-types:ipv4-unicast",
        "ipv6" => "iana-bgp-types:ipv6-unicast",
        _ => return Err(format!("Unsupported address family: {}", afi).into()),
    };

    let afi_xpath = format!("afi-safis/afi-safi[name='{}']/prefixes", afi);

    YangTableBuilder::new(session, proto::get_request::DataType::All)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(PROTOCOL_BGP))
        .column_leaf("Instance", "name")
        .xpath(XPATH_BGP_NEIGHBOR)
        .column_leaf("Description", "description")
        .column_leaf("Neighbor", "remote-address")
        .column_leaf("AS", "peer-as")
        .column_leaf("State", "session-state")
        .column_from_fn(
            "Up/Down",
            Box::new(|dnode| {
                let Some(last_established) =
                    dnode.child_opt_value("last-established")
                else {
                    return "-".to_owned();
                };
                let last_established =
                    DateTime::parse_from_rfc3339(last_established.as_str())
                        .unwrap_or_default();
                let now = Utc::now();
                let delta =
                    now.signed_duration_since(last_established).num_seconds();
                uptime_from_secs(delta).to_string()
            }),
        )
        .column_from_fn(
            "Pfx\nRcd/Acc",
            Box::new(move |dnode| {
                let Some(pfxs) = dnode.find_path(&afi_xpath).ok() else {
                    return "- / -".to_owned();
                };
                let rcvd = pfxs.child_value("received");
                let acptd = pfxs.child_value("installed");
                format!("{} / {}", rcvd, acptd)
            }),
        )
        .xpath(XPATH_BGP_NEIGHBOR_STATS)
        .column_leaf("Trans.", "established-transitions")
        .xpath(XPATH_BGP_NEIGHBOR_STATS_MSGS)
        .column_leaf("MsgRcvd", "total-received")
        .column_leaf("MsgSent", "total-sent")
        .show()?;

    Ok(false)
}

fn bgp_get_attrs(
    session: &mut Session,
) -> Result<BTreeMap<String, String>, String> {
    let xpath = format!(
        "{}[type='{}'][name='{}']/{}",
        XPATH_PROTOCOL, PROTOCOL_BGP, "main", XPATH_BGP_RIB_ATTR_SET
    );

    let data =
        fetch_data(session, proto::get_request::DataType::State, &xpath)?;

    let attributes = data
        .find_path(&xpath)
        .unwrap()
        .find_xpath("attr-set")
        .unwrap()
        .map(|dnode| {
            let index = dnode.child_value("index");
            let attrs = dnode.find_path("attributes").unwrap();

            let nexthop =
                attrs.child_opt_value("next-hop").unwrap_or("-".to_owned());
            let med = attrs.child_opt_value("med").unwrap_or("-".to_owned());
            let origin = match attrs.child_opt_value("origin").as_deref() {
                Some("incomplete") => "?",
                Some("igp") => "I",
                Some("egp") => "E",
                Some(origin) => origin,
                None => "",
            }
            .to_owned();

            let lclpref = attrs
                .child_opt_value("local-pref")
                .unwrap_or("-".to_owned());

            let as_path = attrs
                .find_xpath("as-path/segment/member")
                .unwrap()
                .filter_map(|member| member.value_canonical())
                .collect::<Vec<String>>()
                .join(" ");

            (
                index,
                format!(
                    "{:>20} {:>5} {:>9} {} {}",
                    nexthop, med, lclpref, as_path, origin
                ),
            )
        })
        .collect();

    Ok(attributes)
}

pub fn cmd_show_bgp_neighbor(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let attrs = bgp_get_attrs(session).unwrap();

    let neighbor = get_arg(&mut args, "neighbor");
    let rt_type = get_arg(&mut args, "type");
    let afi = get_opt_arg(&mut args, "afi").unwrap_or("ipv4".to_owned());

    let afi = match afi.as_str() {
        "ipv4" => "ipv4-unicast",
        "ipv6" => "ipv6-unicast",
        _ => return Err(format!("Unsupported address family: {}", afi).into()),
    };

    let rt_type = match rt_type.as_str() {
        "received-routes" => "adj-rib-in-pre/routes",
        "advertised-routes" => "adj-rib-out-post/routes",
        _ => unreachable!(),
    };

    let xpath_req = format!(
        "{}[type='{}'][name='{}']/{}[name='iana-bgp-types:{}']/{}/neighbors/neighbor[neighbor-address='{}']/{}",
        XPATH_PROTOCOL,
        PROTOCOL_BGP,
        "main",
        XPATH_BGP_RIB_AFI_SAFI,
        afi,
        afi,
        neighbor,
        rt_type
    );

    let data =
        fetch_data(session, proto::get_request::DataType::State, &xpath_req)?;

    let xpath_routes = format!("{}/route", &xpath_req);

    let output = session.writer();

    writeln!(output, "\nAddress family: {afi}").unwrap();
    writeln!(
        output,
        "{:>20} {:>20} {:>5} {:>5} AS Path",
        "Prefix", "NextHop", "MED", "LocalPref"
    )
    .unwrap();
    for route in data.find_xpath(&xpath_routes).unwrap() {
        let prefix = route.child_opt_value("prefix").unwrap();
        let index = route.child_opt_value("attr-index").unwrap();
        let route_attrs = attrs.get(&index).unwrap();
        writeln!(output, "{:>20} {}", prefix, route_attrs)?;
    }

    Ok(false)
}

fn strip_prefix(input: &str) -> &str {
    match input.split_once(':') {
        Some((_first, remainder)) => remainder,
        None => input,
    }
}

pub fn cmd_show_bgp_neighbor_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let neighbor_addr = get_opt_arg(&mut args, "neighbor");

    let xpath_bgp_instance = format!(
        "{}[type='{}'][name='{}']",
        XPATH_PROTOCOL, PROTOCOL_BGP, "main"
    );

    let mut xpath_neighbor = "ietf-bgp:bgp/neighbors/neighbor".to_owned();
    if let Some(addr) = &neighbor_addr {
        xpath_neighbor =
            format!("{}[remote-address='{}']", xpath_neighbor, addr);
    }

    let data = fetch_data(
        session,
        proto::get_request::DataType::All,
        &xpath_bgp_instance,
    )?;

    let output = session.writer();
    for dnode_inst in data.find_xpath(&xpath_bgp_instance).unwrap() {
        let local_as = dnode_inst.relative_value("ietf-bgp:bgp/global/as");
        let local_rid =
            dnode_inst.relative_value("ietf-bgp:bgp/global/identifier");

        for dnode_nbr in dnode_inst.find_xpath(&xpath_neighbor).unwrap() {
            let remote_addr = dnode_nbr.child_value("remote-address");
            let remote_as = dnode_nbr.child_value("peer-as");
            let peer_type = dnode_nbr.child_value("peer-type");
            let desc = dnode_nbr
                .child_opt_value("description")
                .unwrap_or("-".to_owned());

            writeln!(
                output,
                "BGP neighbor is {}, remote AS {}, {} link",
                remote_addr, remote_as, peer_type
            )
            .unwrap();

            writeln!(output, " Description: {}", desc).unwrap();

            let remote_rid = dnode_nbr.child_value("identifier");
            writeln!(
                output,
                "  BGP version 4, remote router ID {}",
                remote_rid
            )
            .unwrap();

            // Timers
            if let Some(hold_time_str) =
                dnode_nbr.relative_opt_value("timers/negotiated-hold-time")
            {
                let hold_time: u32 = hold_time_str.parse().unwrap_or(0);
                let keepalive = hold_time / 3;
                writeln!(
                    output,
                    "  Hold time is {}, keepalive interval is {} seconds",
                    hold_time, keepalive
                )
                .unwrap();
            }

            let state = dnode_nbr.child_value("session-state");

            let last_established_leaf =
                dnode_nbr.child_value("last-established");
            let last_established =
                DateTime::parse_from_rfc3339(last_established_leaf.as_str())
                    .unwrap();
            let delta = Utc::now()
                .signed_duration_since(last_established)
                .num_seconds();
            let uptime_str = uptime_from_secs(delta);

            writeln!(output, "  BGP state is {}, up for {}", state, uptime_str)
                .unwrap();

            let transitions =
                dnode_nbr.relative_value("statistics/established-transitions");
            writeln!(
                output,
                "  Number of transitions to established: {}",
                transitions
            )
            .unwrap();

            // Capabilities
            writeln!(output, "  Neighbor Capabilities:").unwrap();
            let caps_xpath = "capabilities/negotiated-capabilities";
            if let Ok(iter) = dnode_nbr.find_xpath(caps_xpath) {
                let caps: Vec<String> = iter
                    .map(|n| {
                        let val = n.value_canonical().unwrap_or_default();
                        strip_prefix(&val).to_owned()
                    })
                    .collect();

                if !caps.is_empty() {
                    writeln!(output, "    Options: <{}>", caps.join(" "))
                        .unwrap();
                }
            }

            // Address Families
            let afi_xpath = "afi-safis/afi-safi";
            let mut afi_names = Vec::new();
            if let Ok(afi_iter) = dnode_nbr.find_xpath(afi_xpath) {
                for afi_node in afi_iter {
                    let name = afi_node.child_value("name");
                    afi_names.push(strip_prefix(&name).to_owned());
                }
            }
            if !afi_names.is_empty() {
                writeln!(
                    output,
                    "\n  Address families configured: {}",
                    afi_names.join(" ")
                )
                .unwrap();
            }

            // Message Statistics
            let stats_path = "statistics/messages";
            if let Some(stats_node) = dnode_nbr
                .find_xpath(stats_path)
                .ok()
                .and_then(|mut x| x.next())
            {
                writeln!(output, "\n  Message Statistics:").unwrap();
                writeln!(output, "    {:25} {:>10} {:>10}", "", "Sent", "Rcvd")
                    .unwrap();

                let sent_updates = stats_node.child_value("updates-sent");
                let rcvd_updates = stats_node.child_value("updates-received");
                let sent_notif = stats_node.child_value("notifications-sent");
                let rcvd_notif =
                    stats_node.child_value("notifications-received");
                let sent_total = stats_node.child_value("total-sent");
                let rcvd_total = stats_node.child_value("total-received");

                writeln!(
                    output,
                    "    {:25} {:>10} {:>10}",
                    "Updates:", sent_updates, rcvd_updates
                )
                .unwrap();
                writeln!(
                    output,
                    "    {:25} {:>10} {:>10}",
                    "Notifications:", sent_notif, rcvd_notif
                )
                .unwrap();
                writeln!(
                    output,
                    "    {:25} {:>10} {:>10}",
                    "Total messages:", sent_total, rcvd_total
                )
                .unwrap();
            }

            // Prefix Statistics
            writeln!(output, "\n  Prefix Statistics:").unwrap();
            writeln!(
                output,
                "    {:20} {:>10} {:>10} {:>10}",
                "", "Sent", "Rcvd", "Installed"
            )
            .unwrap();

            if let Ok(afi_iter) = dnode_nbr.find_xpath(afi_xpath) {
                for afi_node in afi_iter {
                    let name = afi_node.child_value("name");
                    let name = strip_prefix(&name).to_owned();

                    let sent = afi_node.relative_value("prefixes/sent");
                    let rcvd = afi_node.relative_value("prefixes/received");
                    let installed =
                        afi_node.relative_value("prefixes/installed");

                    writeln!(
                        output,
                        "    {:20} {:>10} {:>10} {:>10}",
                        name, sent, rcvd, installed
                    )
                    .unwrap();
                }
            }

            // Local/Remote Addresses and Ports
            writeln!(output).unwrap();
            writeln!(
                output,
                " Local AS is {}, local router ID {}",
                local_as, local_rid
            )
            .unwrap();

            let local_addr = dnode_nbr.child_value("local-address");
            let local_port = dnode_nbr.child_value("local-port");
            let remote_port = dnode_nbr.child_value("remote-port");

            writeln!(
                output,
                " Local TCP address is {}, local port is {}",
                local_addr, local_port
            )
            .unwrap();
            writeln!(
                output,
                " Remote TCP address is {}, remote port is {}",
                remote_addr, remote_port
            )
            .unwrap();

            writeln!(output).unwrap();
        }
    }

    Ok(false)
}

// ===== IS-IS "clear" commands =====
pub fn cmd_clear_isis_adjacency(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let yang_ctx = YANG_CTX.get().unwrap();
    let data = r#"{"ietf-isis:clear-adjacency": {}}"#;
    let data = DataTree::parse_op_string(
        yang_ctx,
        data,
        DataFormat::JSON,
        DataParserFlags::empty(),
        DataOperation::RpcYang,
    )
    .expect("Failed to parse data tree");
    let _ = session
        .execute(data)
        .map_err(|error| format!("% failed to invoke RPC: {}", error))?;

    Ok(false)
}

pub fn cmd_clear_isis_database(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let yang_ctx = YANG_CTX.get().unwrap();
    let data = r#"{"ietf-isis:clear-database": {}}"#;
    let data = DataTree::parse_op_string(
        yang_ctx,
        data,
        DataFormat::JSON,
        DataParserFlags::empty(),
        DataOperation::RpcYang,
    )
    .expect("Failed to parse data tree");
    let _ = session
        .execute(data)
        .map_err(|error| format!("% failed to invoke RPC: {}", error))?;

    Ok(false)
}

// ===== BGP "clear" commands =====
const XPATH_BGP_NEIGHBORS_CLEAR: &str = "ietf-bgp:bgp/neighbors/ietf-bgp:clear";

pub fn cmd_clear_bgp_neighbor(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let neighbor = get_opt_arg(&mut args, "neighbor");
    let clear_type = get_opt_arg(&mut args, "type");
    let yang_ctx = YANG_CTX.get().unwrap();

    let xpath = format!(
        "{}[type='{}'][name='{}']/{}",
        XPATH_PROTOCOL, PROTOCOL_BGP, "main", XPATH_BGP_NEIGHBORS_CLEAR
    );

    let mut clear_req = DataTree::new(yang_ctx);
    clear_req.new_path(&xpath, None, false).unwrap();

    if let Some(clear_type) = clear_type {
        let operation = match clear_type.as_str() {
            "soft-in" => "soft-inbound",
            op => op,
        };
        let xpath = format!("{}/{}", &xpath, operation);
        clear_req.new_path(&xpath, None, false).unwrap();
    }

    if neighbor.is_some() {
        let xpath = format!("{}/holo-bgp:remote-addr", &xpath);
        clear_req
            .new_path(&xpath, neighbor.as_deref(), false)
            .unwrap();
    }

    let data = clear_req
        .print_string(DataFormat::JSON, DataPrinterFlags::WD_ALL)
        .unwrap();

    println!("{}", data);

    let data = DataTree::parse_op_string(
        yang_ctx,
        data,
        DataFormat::JSON,
        DataParserFlags::empty(),
        DataOperation::RpcYang,
    )
    .expect("Failed to parse data tree");

    let _ = session
        .execute(data)
        .map_err(|error| format!("% failed to invoke RPC: {}", error))?;

    Ok(false)
}

// ===== "show route" commands =====

fn protocol_display_name(proto: &str) -> &str {
    match proto {
        "ietf-bgp:bgp" => "BGP",
        "ietf-ospf:ospfv2" => "OSPF",
        "ietf-ospf:ospfv3" => "OSPFv3",
        "ietf-isis:isis" => "IS-IS",
        "ietf-rip:ripv2" => "RIP",
        "ietf-rip:ripng" => "RIPng",
        "ietf-routing:direct" => "Direct",
        "ietf-routing:static" => "Static",
        _ => proto,
    }
}

pub fn cmd_show_route(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, CallbackError> {
    let rib_name = get_opt_arg(&mut args, "afi").unwrap_or("ipv4".to_owned());
    let fetch_xpath = format!("{}[name='{}']", XPATH_RIB, rib_name);
    let route_xpath = format!("{}/routes/route", fetch_xpath);

    let data =
        fetch_data(session, proto::get_request::DataType::All, &fetch_xpath)?;

    let Some(dnode) = data.reference() else {
        return Ok(false);
    };

    let output = session.writer();

    for route in dnode.find_xpath(&route_xpath).unwrap() {
        let prefix = route.child_value("destination-prefix");
        let protocol = route.child_value("source-protocol");
        let preference = route.child_value("route-preference");
        let active = route.find_xpath("active").unwrap().next().is_some();
        let last_updated = route.child_opt_value("last-updated");

        let protocol_name = protocol_display_name(&protocol);

        let uptime = last_updated
            .and_then(|ts| DateTime::parse_from_rfc3339(&ts).ok())
            .map(|ts| {
                let delta = Utc::now().signed_duration_since(ts).num_seconds();
                uptime_from_secs(delta)
            })
            .unwrap_or("-".to_owned());

        let active_marker = if active { "*" } else { " " };

        writeln!(
            output,
            "{:<20} {}[{}/{}] {}",
            prefix, active_marker, protocol_name, preference, uptime
        )
        .unwrap();

        let nh_addr = route.relative_opt_value("next-hop/next-hop-address");
        let nh_iface = route.relative_opt_value("next-hop/outgoing-interface");
        match (nh_addr, nh_iface) {
            (Some(addr), Some(iface)) => {
                writeln!(output, "{:>20} >  to {} via {}", "", addr, iface)
                    .unwrap();
            }
            (Some(addr), None) => {
                writeln!(output, "{:>20} >  to {}", "", addr).unwrap();
            }
            (None, Some(iface)) => {
                writeln!(output, "{:>20} >  via {}", "", iface).unwrap();
            }
            (None, None) => {}
        }
    }

    Ok(false)
}
