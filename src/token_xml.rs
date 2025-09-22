//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use indextree::NodeId;
use xml::ParserConfig;
use xml::reader::XmlEvent;

use crate::internal_commands;
use crate::token::{Action, Commands, Token, TokenKind};

pub fn gen_cmds(commands: &mut Commands) {
    // Read embedded XML file containing command definitions.
    let xml = include_str!("internal_commands.xml");
    let reader = ParserConfig::new().create_reader(xml.as_bytes());

    // Iterate over all XML tags.
    let mut stack = vec![];
    for e in reader {
        match e {
            Ok(XmlEvent::StartElement {
                name, attributes, ..
            }) => {
                let token_id = match name.local_name.as_str() {
                    "tree" => parse_tag_tree(commands, attributes),
                    "token" => {
                        let parent = stack.last().unwrap();
                        parse_tag_token(commands, *parent, attributes)
                    }
                    // Ignore unknown tags for now.
                    _ => continue,
                };

                // Update stack of tokens.
                stack.push(token_id);
            }
            Ok(XmlEvent::EndElement { .. }) => {
                // Update stack of tokens.
                stack.pop();
            }
            Ok(_) => (),
            Err(e) => panic!("Error parsing XML document: {:?}", e),
        }
    }
}

fn parse_tag_tree(
    commands: &Commands,
    attributes: Vec<xml::attribute::OwnedAttribute>,
) -> NodeId {
    let name = find_attribute(&attributes, "name");
    match name {
        "exec" => commands.exec_root,
        "config" => commands.config_root_internal,
        "config-default" => commands.config_dflt_internal,
        _ => panic!("unknown tree name: {}", name),
    }
}

fn parse_tag_token(
    commands: &mut Commands,
    parent: NodeId,
    attributes: Vec<xml::attribute::OwnedAttribute>,
) -> NodeId {
    let name = find_attribute(&attributes, "name");
    let help = find_opt_attribute(&attributes, "help");
    let kind = find_opt_attribute(&attributes, "kind");
    let argument = find_opt_attribute(&attributes, "argument");
    let cmd_name = find_opt_attribute(&attributes, "cmd");
    let callback = cmd_name.map(|name| match name {
        "cmd_config" => internal_commands::cmd_config,
        "cmd_list" => internal_commands::cmd_list,
        "cmd_exit_exec" => internal_commands::cmd_exit_exec,
        "cmd_exit_config" => internal_commands::cmd_exit_config,
        "cmd_end" => internal_commands::cmd_end,
        "cmd_pwd" => internal_commands::cmd_pwd,
        "cmd_discard" => internal_commands::cmd_discard,
        "cmd_commit" => internal_commands::cmd_commit,
        "cmd_validate" => internal_commands::cmd_validate,
        "cmd_show_config" => internal_commands::cmd_show_config,
        "cmd_show_config_changes" => internal_commands::cmd_show_config_changes,
        "cmd_show_state" => internal_commands::cmd_show_state,
        "cmd_show_yang_modules" => internal_commands::cmd_show_yang_modules,
        "cmd_show_isis_interface" => internal_commands::cmd_show_isis_interface,
        "cmd_show_isis_adjacency" => internal_commands::cmd_show_isis_adjacency,
        "cmd_show_isis_database" => internal_commands::cmd_show_isis_database,
        "cmd_show_isis_route" => internal_commands::cmd_show_isis_route,
        "cmd_show_ospf_interface" => internal_commands::cmd_show_ospf_interface,
        "cmd_show_ospf_interface_detail" => {
            internal_commands::cmd_show_ospf_interface_detail
        }
        "cmd_show_ospf_vlink" => internal_commands::cmd_show_ospf_vlink,
        "cmd_show_ospf_neighbor" => internal_commands::cmd_show_ospf_neighbor,
        "cmd_show_ospf_neighbor_detail" => {
            internal_commands::cmd_show_ospf_neighbor_detail
        }
        "cmd_show_ospf_database_as" => {
            internal_commands::cmd_show_ospf_database_as
        }
        "cmd_show_ospf_database_area" => {
            internal_commands::cmd_show_ospf_database_area
        }
        "cmd_show_ospf_database_link" => {
            internal_commands::cmd_show_ospf_database_link
        }
        "cmd_show_ospf_route" => internal_commands::cmd_show_ospf_route,
        "cmd_show_ospf_hostnames" => internal_commands::cmd_show_ospf_hostnames,
        "cmd_show_rip_interface" => internal_commands::cmd_show_rip_interface,
        "cmd_show_rip_interface_detail" => {
            internal_commands::cmd_show_rip_interface_detail
        }
        "cmd_show_rip_neighbor" => internal_commands::cmd_show_rip_neighbor,
        "cmd_show_rip_neighbor_detail" => {
            internal_commands::cmd_show_rip_neighbor_detail
        }
        "cmd_show_rip_route" => internal_commands::cmd_show_rip_route,
        "cmd_show_mpls_ldp_discovery" => {
            internal_commands::cmd_show_mpls_ldp_discovery
        }
        "cmd_show_mpls_ldp_discovery_detail" => {
            internal_commands::cmd_show_mpls_ldp_discovery_detail
        }
        "cmd_show_mpls_ldp_peer" => internal_commands::cmd_show_mpls_ldp_peer,
        "cmd_show_mpls_ldp_peer_detail" => {
            internal_commands::cmd_show_mpls_ldp_peer_detail
        }
        "cmd_show_mpls_ldp_binding_address" => {
            internal_commands::cmd_show_mpls_ldp_binding_address
        }
        "cmd_show_mpls_ldp_binding_fec" => {
            internal_commands::cmd_show_mpls_ldp_binding_fec
        }
        "cmd_clear_isis_adjacency" => {
            internal_commands::cmd_clear_isis_adjacency
        }
        "cmd_clear_isis_database" => internal_commands::cmd_clear_isis_database,
        _ => panic!("unknown command name: {}", name),
    });

    let kind = match kind {
        Some("string") => TokenKind::String,
        Some(_) => panic!("unknown token kind"),
        None => TokenKind::Word,
    };

    let action = callback.map(|callback| Action::Callback(callback));

    // Add new token.
    let token = Token::new(name, help, kind, argument, action, false);

    // Link new token.
    commands.add_token(parent, token)
}

fn find_attribute<'a>(
    attributes: &'a [xml::attribute::OwnedAttribute],
    name: &str,
) -> &'a str {
    find_opt_attribute(attributes, name).unwrap_or_else(|| {
        panic!("Failed to find mandatory {} XML attribute", name)
    })
}

fn find_opt_attribute<'a>(
    attributes: &'a [xml::attribute::OwnedAttribute],
    name: &str,
) -> Option<&'a str> {
    attributes
        .iter()
        .find(|attr| attr.name.local_name == name)
        .map(|attr| attr.value.as_str())
}
