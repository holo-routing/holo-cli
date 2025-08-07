//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::fmt::Write;
use std::process::{Child, Command, Stdio};

use indextree::NodeId;
use prettytable::{Table, format, row};
use similar::TextDiff;
use yang3::data::{
    Data, DataFormat, DataNodeRef, DataParserFlags, DataPrinterFlags, DataTree,
    DataValidationFlags,
};
use yang3::schema::SchemaNodeKind;

use crate::YANG_CTX;
use crate::client::{DataType, DataValue};
use crate::parser::ParsedArgs;
use crate::session::{CommandMode, ConfigurationType, Session};
use crate::token::{Commands, TokenKind};

const XPATH_PROTOCOL: &str =
    "/ietf-routing:routing/control-plane-protocols/control-plane-protocol";

struct YangTableBuilder<'a> {
    session: &'a mut Session,
    data_type: DataType,
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
    pub fn new(session: &'a mut Session, data_type: DataType) -> Self {
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
    pub fn show(self) -> Result<(), String> {
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

        // Print the table to stdout.
        if let Err(error) = page_table(self.session, &table) {
            println!("% failed to display data: {}", error);
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

fn pager() -> Result<Child, std::io::Error> {
    Command::new("less")
        // Exit immediately if the data fits on one screen.
        .arg("-F")
        // Do not clear the screen on exit.
        .arg("-X")
        .stdin(Stdio::piped())
        .spawn()
}

fn page_output(session: &Session, data: &str) -> Result<(), std::io::Error> {
    if session.use_pager() {
        use std::io::Write;

        // Spawn the pager process.
        let mut pager = pager()?;

        // Feed the data to the pager.
        pager.stdin.as_mut().unwrap().write_all(data.as_bytes())?;

        // Wait for the pager process to finish.
        pager.wait()?;
    } else {
        // Print the data directly to the console.
        println!("{}", data);
    }

    Ok(())
}

fn page_table(session: &Session, table: &Table) -> Result<(), std::io::Error> {
    if table.is_empty() {
        return Ok(());
    }

    if session.use_pager() {
        use std::io::Write;

        // Spawn the pager process.
        let mut pager = pager()?;

        // Print the table.
        let mut output = Vec::new();
        table.print(&mut output)?;
        writeln!(output)?;

        // Feed the data to the pager.
        pager.stdin.as_mut().unwrap().write_all(&output)?;

        // Wait for the pager process to finish.
        pager.wait()?;
    } else {
        // Print the table directly to the console.
        table.printstd();
        println!();
    }

    Ok(())
}

fn fetch_data(
    session: &mut Session,
    data_type: DataType,
    xpath: &str,
) -> Result<DataTree<'static>, String> {
    let yang_ctx = YANG_CTX.get().unwrap();
    let data_format = DataFormat::LYB;
    let data = session
        .get(data_type, data_format, true, Some(xpath.to_owned()))
        .map_err(|error| format!("% failed to fetch state data: {}", error))?;
    DataTree::parse_string(
        yang_ctx,
        data.as_bytes(),
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

pub(crate) fn cmd_config(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    let mode = CommandMode::Configure { nodes: vec![] };
    session.mode_set(mode);
    Ok(false)
}

// ===== "exit" =====

pub(crate) fn cmd_exit_exec(
    _commands: &Commands,
    _session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    // Do nothing.
    Ok(true)
}

pub(crate) fn cmd_exit_config(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    session.mode_config_exit();
    Ok(false)
}

// ===== "end" =====

pub(crate) fn cmd_end(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    session.mode_set(CommandMode::Operational);
    Ok(false)
}

// ===== "list" =====

pub(crate) fn cmd_list(
    commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    match session.mode() {
        CommandMode::Operational => {
            // List EXEC-level commands.
            cmd_list_root(commands, &commands.exec_root);
        }
        CommandMode::Configure { .. } => {
            // List internal configuration commands first.
            cmd_list_root(commands, &commands.config_dflt_internal);
            println!("---");
            cmd_list_root(commands, &commands.config_root_internal);
            println!("---");
            // List YANG configuration commands.
            cmd_list_root(commands, &session.mode().token(commands));
        }
    }

    Ok(false)
}

pub(crate) fn cmd_list_root(commands: &Commands, top_token_id: &NodeId) {
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

        println!("{}", cmd_string);
    }
}

// ===== "pwd" =====

pub(crate) fn cmd_pwd(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    println!(
        "{}",
        session.mode().data_path().unwrap_or_else(|| "/".to_owned())
    );
    Ok(false)
}

// ===== "discard" =====

pub(crate) fn cmd_discard(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    session.candidate_discard();
    Ok(false)
}

// ===== "commit" =====

pub(crate) fn cmd_commit(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
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

pub(crate) fn cmd_validate(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
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

pub(crate) fn cmd_show_config(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
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
    if let Err(error) = page_output(session, &data) {
        println!("% failed to print configuration: {}", error)
    }

    Ok(false)
}

pub(crate) fn cmd_show_config_changes(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
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

pub(crate) fn cmd_show_state(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let xpath = get_opt_arg(&mut args, "xpath");
    let format = get_opt_arg(&mut args, "format");
    let format = match format.as_deref() {
        Some("json") => DataFormat::JSON,
        Some("xml") => DataFormat::XML,
        Some(_) => panic!("unknown format"),
        None => DataFormat::JSON,
    };

    match session.get(DataType::State, format, false, xpath) {
        Ok(DataValue::String(data)) => {
            if let Err(error) = page_output(session, &data) {
                println!("% failed to print state data: {}", error)
            }
        }
        Ok(DataValue::Binary(_)) => unreachable!(),
        Err(error) => println!("% failed to fetch state data: {}", error),
    }

    Ok(false)
}

// ===== "show yang modules" =====

pub(crate) fn cmd_show_yang_modules(
    _commands: &Commands,
    _session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
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

pub(crate) fn cmd_show_isis_interface(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    YangTableBuilder::new(session, DataType::All)
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

pub(crate) fn cmd_show_isis_adjacency(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let hostnames = isis_hostnames(session)?;
    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_isis_database(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    let hostnames = isis_hostnames(session)?;
    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_isis_route(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    YangTableBuilder::new(session, DataType::State)
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
    let data = fetch_data(session, DataType::State, &xpath)?;

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
const XPATH_OSPF_NEIGHBOR: &str = "neighbors/neighbor";
const XPATH_OSPF_RIB: &str = "ietf-ospf:ospf/local-rib/route";
const XPATH_OSPF_NEXTHOP: &str = "next-hops/next-hop";
const XPATH_OSPF_HOSTNAMES: &str =
    "ietf-ospf:ospf/holo-ospf:hostnames/hostname";

pub(crate) fn cmd_show_ospf_interface(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    YangTableBuilder::new(session, DataType::All)
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

pub(crate) fn cmd_show_ospf_interface_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let mut output = String::new();

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
    let data = fetch_data(session, DataType::All, xpath_req)?;

    // Iterate over OSPF instances.
    for dnode in data.find_xpath(&xpath_instance).unwrap() {
        let instance = dnode.child_value("name");

        // Iterate over OSPF areas.
        for dnode in dnode.find_xpath(xpath_area).unwrap() {
            let area = dnode.child_value("area-id");

            // Iterate over OSPF interfaces.
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

    if let Err(error) = page_output(session, &output) {
        println!("% failed to print data: {}", error)
    }

    Ok(false)
}

pub(crate) fn cmd_show_ospf_neighbor(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let hostnames = ospf_hostnames(session, protocol)?;
    YangTableBuilder::new(session, DataType::All)
        .xpath(XPATH_PROTOCOL)
        .filter_list_key("type", Some(protocol))
        .column_leaf("Instance", "name")
        .xpath(XPATH_OSPF_AREA)
        .column_leaf("Area", "area-id")
        .xpath(XPATH_OSPF_INTERFACE)
        .column_leaf("Interface", "name")
        .xpath(XPATH_OSPF_NEIGHBOR)
        .filter_list_key(
            "neighbor-router-id=",
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

pub(crate) fn cmd_show_ospf_neighbor_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let mut output = String::new();

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
    let data = fetch_data(session, DataType::All, xpath_req)?;

    // Iterate over OSPF instances.
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

    if let Err(error) = page_output(session, &output) {
        println!("% failed to print data: {}", error)
    }

    Ok(false)
}

pub(crate) fn cmd_show_ospf_database_as(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let hostnames = ospf_hostnames(session, protocol)?;
    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_ospf_database_area(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let hostnames = ospf_hostnames(session, protocol)?;
    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_ospf_database_link(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    let hostnames = ospf_hostnames(session, protocol)?;
    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_ospf_route(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };
    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_ospf_hostnames(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ospfv2" => PROTOCOL_OSPFV2,
        "ospfv3" => PROTOCOL_OSPFV3,
        _ => unreachable!(),
    };

    YangTableBuilder::new(session, DataType::State)
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
    let data = fetch_data(session, DataType::State, &xpath)?;

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

pub(crate) fn cmd_show_rip_interface(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    // Parse arguments.
    let protocol = match get_arg(&mut args, "protocol").as_str() {
        "ripv2" => PROTOCOL_RIPV2,
        "ripng" => PROTOCOL_RIPNG,
        _ => unreachable!(),
    };
    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_rip_interface_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let mut output = String::new();

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

    let data = fetch_data(session, DataType::State, xpath_req)?;

    // Iterate over RIP instances.
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

    if let Err(error) = page_output(session, &output) {
        println!("% failed to print data: {}", error)
    }

    Ok(false)
}

pub(crate) fn cmd_show_rip_neighbor(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    // Parse arguments.
    let (protocol, afi, address) = match get_arg(&mut args, "protocol").as_str()
    {
        "ripv2" => (PROTOCOL_RIPV2, AFI4, "ipv4-address"),
        "ripng" => (PROTOCOL_RIPNG, AFI6, "ipv6-address"),
        _ => unreachable!(),
    };

    let xpath_rip_neighbor = format!("ietf-rip:rip/{}/neighbors/neighbor", afi);

    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_rip_neighbor_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let mut output = String::new();

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

    let data = fetch_data(session, DataType::State, xpath_req)?;

    // Iterate over RIP instances.
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

    if let Err(error) = page_output(session, &output) {
        println!("% failed to print data: {}", error)
    }

    Ok(false)
}

pub(crate) fn cmd_show_rip_route(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    // Parse arguments.
    let (protocol, afi, prefix) = match get_arg(&mut args, "protocol").as_str()
    {
        "ripv2" => (PROTOCOL_RIPV2, AFI4, "ipv4-prefix"),
        "ripng" => (PROTOCOL_RIPNG, AFI6, "ipv6-prefix"),
        _ => unreachable!(),
    };

    let xpath_rip_rib = format!("ietf-rip:rip/{}/routes/route", afi);

    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_mpls_ldp_discovery(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_mpls_ldp_discovery_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let mut output = String::new();

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

    let data = fetch_data(session, DataType::State, xpath_req)?;

    // Iterate over MPLS LDP instances.
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

    if let Err(error) = page_output(session, &output) {
        println!("% failed to print data: {}", error)
    }

    Ok(false)
}

pub(crate) fn cmd_show_mpls_ldp_peer(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_mpls_ldp_peer_detail(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let mut output = String::new();

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

    let data = fetch_data(session, DataType::State, xpath_req)?;

    // Iterate over MPLS LDP instances.
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

    if let Err(error) = page_output(session, &output) {
        println!("% failed to print data: {}", error)
    }

    Ok(false)
}

pub(crate) fn cmd_show_mpls_ldp_binding_address(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    YangTableBuilder::new(session, DataType::State)
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

pub(crate) fn cmd_show_mpls_ldp_binding_fec(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    YangTableBuilder::new(session, DataType::State)
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
