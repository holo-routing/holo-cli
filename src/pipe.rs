//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::fmt;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;

// ===== type aliases =====

type BuiltinFn = fn(
    args: &[String],
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
) -> Result<(), String>;

// ===== data types =====

pub enum PipeAction {
    External { binary: &'static str },
    Builtin(BuiltinFn),
}

pub struct PipeCommand {
    pub name: &'static str,
    pub help: &'static str,
    pub args: &'static [&'static str],
    pub action: PipeAction,
}

pub struct ParsedPipe {
    pub command_idx: usize,
    pub args: Vec<String>,
}

pub struct PipeRegistry {
    commands: Vec<PipeCommand>,
}

#[derive(Debug)]
pub enum PipeError {
    NotFound(String),
    Ambiguous(String, Vec<String>),
    WrongArgCount {
        command: String,
        expected: usize,
        got: usize,
    },
    NotAllowed,
    Io(std::io::Error),
    Spawn {
        command: String,
        source: std::io::Error,
    },
    ThreadPanicked,
    Filter(String),
}

enum PipeStage {
    Thread(JoinHandle<Result<(), String>>),
    Process(Child),
}

pub struct PipeChain {
    writer: Option<Box<dyn Write + Send>>,
    stages: Vec<PipeStage>,
    pager: Option<Child>,
}

// ===== impl PipeRegistry =====

impl PipeRegistry {
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
        }
    }

    pub fn builtin(
        mut self,
        name: &'static str,
        help: &'static str,
        args: &'static [&'static str],
        func: BuiltinFn,
    ) -> Self {
        self.commands.push(PipeCommand {
            name,
            help,
            args,
            action: PipeAction::Builtin(func),
        });
        self
    }

    pub fn external(
        mut self,
        name: &'static str,
        help: &'static str,
        binary: &'static str,
        args: &'static [&'static str],
    ) -> Self {
        self.commands.push(PipeCommand {
            name,
            help,
            args,
            action: PipeAction::External { binary },
        });
        self
    }

    pub fn build(self) -> Self {
        self
    }

    pub fn commands(&self) -> &[PipeCommand] {
        &self.commands
    }

    pub fn find(&self, name: &str) -> Result<usize, PipeError> {
        let matches: Vec<usize> = self
            .commands
            .iter()
            .enumerate()
            .filter(|(_, cmd)| cmd.name.starts_with(name))
            .map(|(i, _)| i)
            .collect();

        match matches.len() {
            0 => Err(PipeError::NotFound(name.to_owned())),
            1 => Ok(matches[0]),
            _ => {
                // Check for exact match.
                for &idx in &matches {
                    if self.commands[idx].name == name {
                        return Ok(idx);
                    }
                }
                let names = matches
                    .iter()
                    .map(|&i| self.commands[i].name.to_owned())
                    .collect();
                Err(PipeError::Ambiguous(name.to_owned(), names))
            }
        }
    }

    pub fn parse_pipe(&self, segment: &str) -> Result<ParsedPipe, PipeError> {
        let mut words = split_words(segment);
        let name = if words.is_empty() {
            String::new()
        } else {
            words.remove(0)
        };
        let idx = self.find(&name)?;
        let args = words;
        let cmd = &self.commands[idx];
        let expected = cmd.args.len();
        if matches!(cmd.action, PipeAction::External { .. }) {
            // External: args specifies minimum required arguments.
            if args.len() < expected {
                return Err(PipeError::WrongArgCount {
                    command: cmd.name.to_owned(),
                    expected,
                    got: args.len(),
                });
            }
        } else if args.len() != expected {
            return Err(PipeError::WrongArgCount {
                command: cmd.name.to_owned(),
                expected,
                got: args.len(),
            });
        }
        Ok(ParsedPipe {
            command_idx: idx,
            args,
        })
    }

    pub fn parse_pipes(
        &self,
        segments: &[&str],
    ) -> Result<Vec<ParsedPipe>, PipeError> {
        segments.iter().map(|seg| self.parse_pipe(seg)).collect()
    }
}

// ===== impl PipeError =====

impl fmt::Display for PipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipeError::NotFound(name) => {
                write!(f, "unknown pipe command: '{}'", name)
            }
            PipeError::Ambiguous(name, matches) => {
                write!(
                    f,
                    "ambiguous pipe command '{}': {}",
                    name,
                    matches.join(", ")
                )
            }
            PipeError::WrongArgCount {
                command,
                expected,
                got,
            } => {
                write!(
                    f,
                    "pipe command '{}' expects {} argument(s), \
                     got {}",
                    command, expected, got
                )
            }
            PipeError::NotAllowed => {
                write!(f, "pipes are not supported for this command")
            }
            PipeError::Io(e) => {
                write!(f, "pipe I/O error: {}", e)
            }
            PipeError::Spawn { command, source } => {
                write!(f, "failed to spawn '{}': {}", command, source)
            }
            PipeError::ThreadPanicked => {
                write!(f, "pipe thread panicked")
            }
            PipeError::Filter(e) => {
                write!(f, "pipe filter error: {}", e)
            }
        }
    }
}

// ===== builtin filters =====

pub fn filter_include(
    args: &[String],
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
) -> Result<(), String> {
    let pattern = &args[0];
    let reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.contains(pattern.as_str()) {
            writeln!(writer, "{}", line).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub fn filter_exclude(
    args: &[String],
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
) -> Result<(), String> {
    let pattern = &args[0];
    let reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        if !line.contains(pattern.as_str()) {
            writeln!(writer, "{}", line).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub fn filter_count(
    _args: &[String],
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
) -> Result<(), String> {
    let reader = BufReader::new(reader);
    let count = reader.lines().count();
    let mut writer = BufWriter::new(writer);
    writeln!(writer, "{}", count).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn filter_no_more(
    _args: &[String],
    reader: Box<dyn Read + Send>,
    mut writer: Box<dyn Write + Send>,
) -> Result<(), String> {
    let mut reader = reader;
    std::io::copy(&mut reader, &mut writer).map_err(|e| e.to_string())?;
    Ok(())
}

// ===== pager =====

fn spawn_pager() -> Result<Child, std::io::Error> {
    Command::new("less")
        .arg("-F")
        .arg("-X")
        .stdin(Stdio::piped())
        .spawn()
}

// ===== default registry =====

pub fn default_registry() -> PipeRegistry {
    PipeRegistry::new()
        .builtin(
            "include",
            "Filter lines matching pattern",
            &["pattern"],
            filter_include,
        )
        .builtin(
            "exclude",
            "Remove lines matching pattern",
            &["pattern"],
            filter_exclude,
        )
        .builtin("count", "Count output lines", &[], filter_count)
        .builtin("no-more", "Disable pager", &[], filter_no_more)
        .external("grep", "Filter lines using grep", "grep", &["PATTERN"])
        .build()
}

// ===== pipe chain =====

/// Output sink that can be converted to either `Stdio` (for external
/// processes) or `Box<dyn Write + Send>` (for builtin threads).
enum ChainOutput {
    ChildStdin(std::process::ChildStdin),
    PipeWriter(std::io::PipeWriter),
    Terminal,
}

impl ChainOutput {
    fn into_stdio(self) -> Stdio {
        match self {
            ChainOutput::ChildStdin(s) => Stdio::from(s),
            ChainOutput::PipeWriter(w) => Stdio::from(w),
            ChainOutput::Terminal => Stdio::inherit(),
        }
    }

    fn into_writer(self) -> Box<dyn Write + Send> {
        match self {
            ChainOutput::ChildStdin(s) => Box::new(s),
            ChainOutput::PipeWriter(w) => Box::new(w),
            ChainOutput::Terminal => Box::new(std::io::stdout()),
        }
    }
}

impl PipeChain {
    pub fn spawn(
        registry: &PipeRegistry,
        pipes: &[ParsedPipe],
        use_pager: bool,
    ) -> Result<Self, PipeError> {
        let has_no_more = pipes
            .iter()
            .any(|p| registry.commands()[p.command_idx].name == "no-more");
        let should_page = use_pager && !has_no_more;

        let mut stages: Vec<PipeStage> = Vec::new();

        // Determine the final output destination.
        let (mut next_output, pager) = if should_page {
            let mut pager = spawn_pager().map_err(|e| PipeError::Spawn {
                command: "less".to_owned(),
                source: e,
            })?;
            let stdin = pager.stdin.take().ok_or_else(|| {
                PipeError::Io(std::io::Error::other("pager has no stdin"))
            })?;
            (ChainOutput::ChildStdin(stdin), Some(pager))
        } else {
            (ChainOutput::Terminal, None)
        };

        // Build the chain backwards (last pipe first).
        for parsed in pipes.iter().rev() {
            let cmd = &registry.commands()[parsed.command_idx];

            // Skip no-more — it's handled by the pager logic.
            if cmd.name == "no-more" {
                continue;
            }

            match &cmd.action {
                PipeAction::External { binary } => {
                    let mut child = Command::new(binary)
                        .args(&parsed.args)
                        .stdin(Stdio::piped())
                        .stdout(next_output.into_stdio())
                        .spawn()
                        .map_err(|e| PipeError::Spawn {
                            command: binary.to_string(),
                            source: e,
                        })?;
                    let child_stdin = child.stdin.take().ok_or_else(|| {
                        PipeError::Io(std::io::Error::other(format!(
                            "'{}' process has no stdin",
                            binary
                        )))
                    })?;
                    next_output = ChainOutput::ChildStdin(child_stdin);
                    stages.push(PipeStage::Process(child));
                }
                PipeAction::Builtin(func) => {
                    let (pipe_reader, pipe_writer) =
                        std::io::pipe().map_err(PipeError::Io)?;
                    let func = *func;
                    let args = parsed.args.clone();
                    let writer_out = next_output.into_writer();
                    let handle = std::thread::spawn(move || {
                        func(&args, Box::new(pipe_reader), writer_out)
                    });
                    next_output = ChainOutput::PipeWriter(pipe_writer);
                    stages.push(PipeStage::Thread(handle));
                }
            }
        }

        Ok(PipeChain {
            writer: Some(next_output.into_writer()),
            stages,
            pager,
        })
    }

    pub fn take_writer(&mut self) -> Option<Box<dyn Write + Send>> {
        self.writer.take()
    }

    pub fn finish(mut self) -> Result<(), PipeError> {
        // Drop writer to signal EOF to the first pipe stage.
        drop(self.writer.take());

        // Wait for all stages (in reverse order — first spawned
        // last).
        for stage in self.stages.drain(..).rev() {
            match stage {
                PipeStage::Thread(handle) => match handle.join() {
                    Ok(result) => result.map_err(PipeError::Filter)?,
                    Err(_) => return Err(PipeError::ThreadPanicked),
                },
                PipeStage::Process(mut child) => {
                    child.wait().map_err(PipeError::Io)?;
                }
            }
        }

        // Wait for pager if present.
        if let Some(mut pager) = self.pager.take() {
            pager.wait().map_err(PipeError::Io)?;
        }

        Ok(())
    }
}

// ===== helper functions =====

/// Split a string on a delimiter, respecting double-quoted segments.
/// Quotes are preserved in the output slices.
fn split_unquoted(s: &str, delim: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    for (i, c) in s.char_indices() {
        if c == '"' {
            in_quote = !in_quote;
        } else if c == delim && !in_quote {
            parts.push(&s[start..i]);
            start = i + c.len_utf8();
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Split words on whitespace, respecting double-quoted segments.
/// Quotes are stripped from the returned strings.
fn split_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    for c in s.chars() {
        if c == '"' {
            in_quote = !in_quote;
        } else if c.is_whitespace() && !in_quote {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

pub fn split_on_pipes(line: &str) -> (&str, Vec<&str>) {
    let parts = split_unquoted(line, '|');
    let base = parts[0].trim();
    if parts.len() > 1 {
        let pipes: Vec<&str> = parts[1..].iter().map(|s| s.trim()).collect();
        (base, pipes)
    } else {
        (base, vec![])
    }
}
