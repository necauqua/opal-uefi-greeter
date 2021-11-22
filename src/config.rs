use alloc::{string::String, vec::Vec};
use core::str;
use log::LevelFilter;

use crate::error::{Error, Result};

fn verbs(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .filter_map(|line| {
            // strip leading whitespace
            let line = line.trim_start();
            // then strip comments
            let line = line
                .match_indices('#')
                .next()
                .map(|(idx, _)| &line[..idx])
                .unwrap_or(line);
            // and then strip trailing whitespace
            let line = line.trim_end();
            // ignore the lines that are now empty
            if line.is_empty() {
                return None;
            }
            let mut split = line.splitn(2, ' ');
            let name = split.next().unwrap(); // splitn never returns empty iter
            let verb = split.next().unwrap_or_default().trim();

            // strip matching single quotes *once* to allow trailing whitespace for prompts
            let verb = verb
                .strip_prefix('\'')
                .and_then(|verb| verb.strip_suffix('\''))
                .unwrap_or(verb);
            Some((name, verb))
        })
        .collect()
}

fn optional(verbs: &[(&str, &str)], verb: &str, joiner: Option<char>) -> Option<String> {
    let mut result = None;
    verbs
        .iter()
        .filter_map(|(&ref v, arg)| (v == verb).then_some(arg))
        .for_each(|verb| {
            let result = result.get_or_insert_with(|| String::with_capacity(256));
            result.push_str(verb);
            if let Some(joiner) = joiner {
                result.push(joiner);
            }
        });
    // remove last joiner
    if joiner.is_some() {
        if let Some(result) = result.as_mut() {
            result.pop();
        }
    }
    result
}

fn required(verbs: &[(&str, &str)], verb: &'static str, joiner: Option<char>) -> Result<String> {
    optional(verbs, verb, joiner).ok_or(Error::ConfigVerbMissing(verb))
}

#[derive(Debug)]
pub struct Config {
    pub image: String,
    pub args: String,
    pub log_level: LevelFilter,
    pub prompt: Option<String>,
    pub retry_prompt: Option<String>,
    pub sed_locked_msg: Option<String>,
    pub clear_on_retry: bool,
}

impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let verbs = verbs(str::from_utf8(bytes).or(Err(Error::ConfigNonUtf8))?);
        let args = required(&verbs, "arg", Some(' '))?;
        Ok(Self {
            image: required(&verbs, "image", Some('\\'))?,
            args,
            log_level: match optional(&verbs, "log-level", None).as_deref() {
                None => LevelFilter::Info,
                Some("error") => LevelFilter::Error,
                Some("warn") => LevelFilter::Warn,
                Some("info") => LevelFilter::Info,
                Some("debug") => LevelFilter::Debug,
                Some("trace") => LevelFilter::Trace,
                Some(x) => {
                    log::warn!("unknown log-level type '{}', defaulting to info", x);
                    LevelFilter::Info
                }
            },
            prompt: optional(&verbs, "prompt", None),
            retry_prompt: optional(&verbs, "retry-prompt", None),
            sed_locked_msg: optional(&verbs, "sed-locked-msg", None),
            clear_on_retry: optional(&verbs, "clear-on-retry", None).as_deref() == Some("on"),
        })
    }
}
