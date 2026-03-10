//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use indextree::NodeId;
use itertools::Itertools;
use reedline::{
    ColumnarMenu, Completer, FileBackedHistory, KeyCode, KeyModifiers,
    MenuBuilder, Prompt, PromptEditMode, PromptHistorySearch,
    PromptHistorySearchStatus, Reedline, ReedlineEvent, ReedlineMenu, Span,
    Suggestion, Vi,
};

use crate::Cli;
use crate::error::ParserError;
use crate::parser::{self, ParsedCommand};
use crate::pipe::PipeRegistry;
use crate::token::{Commands, TokenKind, is_pipeable};

static DEFAULT_PROMPT_INDICATOR: &str = "# ";
static DEFAULT_MULTILINE_INDICATOR: &str = "::: ";
static DEFAULT_HISTORY_SIZE: usize = 1000;
static DEFAULT_HISTORY_FILENAME: &str = "history.txt";

#[derive(Clone)]
pub struct CliPrompt(String);

#[derive(Clone)]
pub struct CliCompleter(Arc<Mutex<Cli>>);

// ===== impl CliPrompt =====

impl CliPrompt {
    pub fn new(string: String) -> Self {
        Self(string)
    }

    pub fn update(&mut self, string: String) {
        self.0 = string;
    }
}

impl Prompt for CliPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Owned(self.0.clone())
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(
        &self,
        _edit_mode: PromptEditMode,
    ) -> Cow<'_, str> {
        DEFAULT_PROMPT_INDICATOR.into()
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        DEFAULT_MULTILINE_INDICATOR.into()
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
        let prefix = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };
        Cow::Owned(format!(
            "({}reverse-search: {}) ",
            prefix, history_search.term
        ))
    }
}

// ===== impl CliCompleter =====

impl Completer for CliCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let cli = self.0.lock().unwrap();

        // Check if we're completing after a pipe character.
        let line_to_pos = &line[..pos];
        if let Some(pipe_pos) = line_to_pos.rfind('|') {
            // Parse the base command (before the first pipe) to
            // check if it supports pipes.
            let base_cmd = line_to_pos.split('|').next().unwrap_or("").trim();
            let wd = cli.session.mode().token(&cli.commands);
            let pipeable = match parser::parse_command_try(
                &cli.session,
                &cli.commands,
                wd,
                base_cmd,
            ) {
                Ok(parsed) => is_pipeable(&cli.commands, parsed.token_id),
                Err(ParserError::Incomplete(tid)) => {
                    is_pipeable(&cli.commands, tid)
                }
                _ => false,
            };
            if !pipeable {
                return vec![];
            }
            let after_pipe = line_to_pos[pipe_pos + 1..].trim_start();
            return complete_pipe(&cli.commands.pipe_registry, after_pipe, pos);
        }

        let last_word = line.split_whitespace().last().unwrap_or(line);
        let partial = line
            .chars()
            .last()
            .map(|c| !c.is_whitespace())
            .unwrap_or(false);

        let wd_token_id = cli.session.mode().token(&cli.commands);
        let completions = match parser::parse_command_try(
            &cli.session,
            &cli.commands,
            wd_token_id,
            line,
        ) {
            Ok(ParsedCommand { token_id, .. })
            | Err(ParserError::Incomplete(token_id)) => {
                if partial {
                    complete_add_token(
                        &cli.commands,
                        token_id,
                        partial,
                        last_word,
                    )
                } else {
                    let token_ids = token_id.children(&cli.commands.arena);
                    complete_add_tokens(&cli.commands, partial, token_ids)
                }
            }
            Err(ParserError::Ambiguous(token_ids)) => {
                complete_add_tokens(&cli.commands, partial, token_ids)
            }
            _ => vec![],
        };

        completions
            .into_iter()
            .map(|(value, description)| Suggestion {
                value,
                description,
                extra: None,
                span: Span {
                    start: if partial { pos - last_word.len() } else { pos },
                    end: pos,
                },
                append_whitespace: true,
                style: None,
            })
            .collect()
    }
}

// ===== global functions =====

pub fn reedline_init(
    cli: Arc<Mutex<Cli>>,
    use_ansi_coloring: bool,
) -> Reedline {
    let history = Box::new(
        FileBackedHistory::with_file(
            DEFAULT_HISTORY_SIZE,
            DEFAULT_HISTORY_FILENAME.into(),
        )
        .expect("Error configuring history with file"),
    );
    let completer = Box::new(CliCompleter(cli));
    let completion_menu =
        Box::new(ColumnarMenu::default().with_name("completion_menu"));

    let mut insert_keybindings = reedline::default_vi_insert_keybindings();
    let normal_keybindings = reedline::default_vi_normal_keybindings();

    // <Tab> as completion trigger
    insert_keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );

    // <?> as completion trigger
    insert_keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Char('?'),
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    insert_keybindings.add_binding(
        KeyModifiers::CONTROL,
        KeyCode::Char('z'),
        ReedlineEvent::ExecuteHostCommand("end".to_owned()),
    );

    let edit_mode = Box::new(Vi::new(insert_keybindings, normal_keybindings));
    Reedline::create()
        .with_history(history)
        .with_ansi_colors(use_ansi_coloring)
        .with_completer(completer)
        .with_quick_completions(true)
        .with_partial_completions(true)
        .with_edit_mode(edit_mode)
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
}

fn complete_pipe(
    registry: &PipeRegistry,
    after_pipe: &str,
    pos: usize,
) -> Vec<Suggestion> {
    let words: Vec<&str> = after_pipe.split_whitespace().collect();
    let first_word = words.first().copied().unwrap_or("");

    // Check if cursor is at a partial word or after whitespace.
    let partial = after_pipe
        .chars()
        .last()
        .map(|c| !c.is_whitespace())
        .unwrap_or(false);

    let exact_match =
        registry.commands().iter().any(|cmd| cmd.name == first_word);

    if exact_match && (words.len() > 1 || !partial) {
        // Command is fully entered — show arg hints if needed.
        if let Ok(idx) = registry.find(first_word) {
            let cmd = &registry.commands()[idx];
            // Count args already provided (excluding the command
            // word and any partial word being typed).
            let provided = if partial {
                words.len() - 2
            } else {
                words.len() - 1
            };
            // Show remaining arg hints if not typing a value.
            if !partial && provided < cmd.args.len() {
                return cmd.args[provided..]
                    .iter()
                    .map(|arg| Suggestion {
                        value: arg.to_uppercase(),
                        description: Some(cmd.help.to_owned()),
                        extra: None,
                        span: Span {
                            start: pos,
                            end: pos,
                        },
                        append_whitespace: true,
                        style: None,
                    })
                    .collect();
            }
        }
        return vec![];
    }

    // Complete pipe command names.
    registry
        .commands()
        .iter()
        .filter(|cmd| first_word.is_empty() || cmd.name.starts_with(first_word))
        .map(|cmd| {
            let span_start = if partial { pos - first_word.len() } else { pos };
            Suggestion {
                value: cmd.name.to_owned(),
                description: Some(cmd.help.to_owned()),
                extra: None,
                span: Span {
                    start: span_start,
                    end: pos,
                },
                append_whitespace: true,
                style: None,
            }
        })
        .collect()
}

fn complete_add_token(
    commands: &Commands,
    token_id: NodeId,
    partial: bool,
    word: &str,
) -> Vec<(String, Option<String>)> {
    let mut completions = vec![];

    let token = commands.get_token(token_id);
    if token.kind == TokenKind::Word && !token.matches(word, true) {
        completions.push((token.name.clone(), token.help.clone()));
    } else if token.kind == TokenKind::String && !partial {
        completions.push((token.name.to_uppercase(), token.help.clone()));
    } else if token.kind == TokenKind::Word && token.matches(word, false) {
        completions.push((token.name.to_lowercase(), token.help.clone()));
    }

    completions
}

fn complete_add_tokens(
    commands: &Commands,
    partial: bool,
    token_ids: impl IntoIterator<Item = NodeId>,
) -> Vec<(String, Option<String>)> {
    token_ids
        .into_iter()
        .filter_map(|token_id| {
            let token = commands.get_token(token_id);
            if token.kind == TokenKind::Word {
                Some((token.name.clone(), token.help.clone()))
            } else if token.kind == TokenKind::String && !partial {
                Some((token.name.to_uppercase(), token.help.clone()))
            } else {
                None
            }
        })
        .sorted()
        .collect()
}
