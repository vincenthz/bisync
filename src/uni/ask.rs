//! Putting each proposed change to the user, one at a time.
//!
//! The interesting part of this tool is not the copying, which is `bisync`'s,
//! but the pause before each change: a run proposes, and a person disposes. So
//! the decision is an interface rather than a function — a terminal
//! implementation for people, whatever a caller likes for a test — and the
//! answers are a small closed set that includes *show me* as well as yes and no.
//!
//! Nothing here reads a file, opens a link or decides anything. [`Prompt`] is a
//! reader and a writer, which is what lets the whole interaction be tested by
//! handing it a string of keystrokes.

use std::io::{self, BufRead, BufReader, Read, Write};

use super::plan::Step;

/// What the user said about one proposed change.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Answer {
    /// Make this change.
    Yes,
    /// Leave this path alone.
    No,
    /// Show what would change, then ask again. Never a final answer.
    Diff,
    /// This one and every one after it.
    All,
    /// Not this one, and stop asking: carry out what has been accepted so far.
    Rest,
    /// Abandon the run. Nothing accepted so far is carried out.
    Quit,
}

/// Where the yes-or-no comes from.
pub trait Ask {
    /// Decide one step. `position` and `total` are for showing progress through
    /// the list; the answer is what matters.
    fn ask(&mut self, step: &Step, position: usize, total: usize) -> io::Result<Answer>;

    /// Show the user something — a diff, or why there is not one. Separate from
    /// [`Ask::ask`] so that the caller, which is the only thing that can fetch
    /// the peer's copy of a file, does the fetching and this does the showing.
    fn note(&mut self, text: &str) -> io::Result<()>;
}

/// The terminal implementation: a line of prose and a single keystroke.
pub struct Prompt<R, W> {
    input: R,
    output: W,
    /// Printed before the first question, and again whenever an unrecognised
    /// key arrives. Not before every question: six changes in and the legend is
    /// noise between the user and the thing they are reading.
    explained: bool,
}

impl Prompt<BufReader<io::Stdin>, io::Stdout> {
    /// Ask on the terminal this process was started from.
    pub fn terminal() -> Self {
        Prompt::new(BufReader::new(io::stdin()), io::stdout())
    }
}

impl<R: Read, W: Write> Prompt<BufReader<R>, W> {
    /// Wrap an unbuffered reader. Reading a prompt answer a byte at a time is
    /// what a naked `Read` would do, and it also has to be buffered for
    /// [`BufRead::read_line`], so the wrapping happens here rather than at every
    /// call site.
    pub fn over(input: R, output: W) -> Self {
        Prompt::new(BufReader::new(input), output)
    }
}

impl<R: BufRead, W: Write> Prompt<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Prompt {
            input,
            output,
            explained: false,
        }
    }

    fn legend(&mut self) -> io::Result<()> {
        writeln!(
            self.output,
            "  y accept   n leave it   d show the difference   a accept the rest\
             \n  s stop asking and apply what is accepted   q abandon the run"
        )
    }
}

impl<R: BufRead, W: Write> Ask for Prompt<R, W> {
    fn ask(&mut self, step: &Step, position: usize, total: usize) -> io::Result<Answer> {
        if !self.explained {
            self.explained = true;
            self.legend()?;
        }
        let detail = step.detail();
        loop {
            write!(
                self.output,
                "[{position}/{total}] {:<7} {}{}  [y/n/d/a/s/q] ",
                step.verb(),
                step.path,
                if detail.is_empty() {
                    String::new()
                } else {
                    format!("  ({detail})")
                }
            )?;
            self.output.flush()?;

            let mut line = String::new();
            if self.input.read_line(&mut line)? == 0 {
                // The terminal went away mid-question. Treating that as consent
                // would be the worst possible reading of it.
                writeln!(
                    self.output,
                    "\nno more input: nothing was changed. Pass --yes to accept every \
                     change, or --dry-run to see them without making any."
                )?;
                return Ok(Answer::Quit);
            }
            match answer_of(&line) {
                Some(answer) => return Ok(answer),
                None => self.legend()?,
            }
        }
    }

    fn note(&mut self, text: &str) -> io::Result<()> {
        // A newline first: the question it follows was left unterminated, and
        // whether the terminal echoed the user's own newline over it is not
        // something this can know.
        writeln!(self.output)?;
        for line in text.lines() {
            writeln!(self.output, "      {line}")?;
        }
        self.output.flush()
    }
}

/// Put every step to whoever is answering, and return the ones they accepted —
/// or `None` if they abandoned the run, in which case nothing at all happens.
///
/// `difference` is called for a `d` and returns whatever should be shown; the
/// caller owns it because fetching the peer's copy of a file is the one part of
/// answering a question that needs the link. `left_alone` is told about steps
/// nobody was asked about, with the reason.
///
/// Two answers carry to other steps, both because a plan is a tree and an answer
/// about a branch is an answer about what hangs off it:
///
/// * A directory refused refuses everything inside it. Creations are ordered
///   parents-first, so accepting a file inside a directory that was declined
///   would quietly create the directory after all.
/// * A path kept keeps the directories above it. Deletions are ordered
///   children-first, so a directory whose contents someone chose to keep cannot
///   go — and finding that out by failing to remove it, having said yes, is a
///   worse way to learn it than not being asked.
pub fn choose(
    steps: Vec<Step>,
    ask: &mut dyn Ask,
    mut difference: impl FnMut(&Step) -> io::Result<String>,
    mut left_alone: impl FnMut(&Step, &str),
) -> io::Result<Option<Vec<Step>>> {
    let total = steps.len();
    let mut accepted: Vec<Step> = Vec::new();
    let mut rest = false;
    let mut declined: Vec<String> = Vec::new();
    let mut kept: Vec<String> = Vec::new();

    for (i, step) in steps.into_iter().enumerate() {
        if let Some(dir) = declined
            .iter()
            .find(|dir| crate::relpath::is_under(&step.path, dir))
        {
            left_alone(&step, &format!("inside {dir}, left alone"));
            continue;
        }
        if step.is_delete() {
            if let Some(inside) = kept
                .iter()
                .find(|path| crate::relpath::is_under(path, &step.path))
            {
                left_alone(&step, &format!("still holds {inside}"));
                continue;
            }
        }
        if rest {
            accepted.push(step);
            continue;
        }
        loop {
            match ask.ask(&step, i + 1, total)? {
                Answer::Yes => {
                    accepted.push(step);
                    break;
                }
                Answer::No => {
                    if matches!(step.to, crate::tree::PathState::Dir) {
                        declined.push(step.path.clone());
                    }
                    if step.is_delete() {
                        kept.push(step.path.clone());
                    }
                    break;
                }
                Answer::All => {
                    rest = true;
                    accepted.push(step);
                    break;
                }
                // Everything after this is left alone, but what was accepted
                // before it still happens.
                Answer::Rest => return Ok(Some(accepted)),
                Answer::Quit => return Ok(None),
                Answer::Diff => {
                    let text = difference(&step)?;
                    ask.note(&text)?;
                }
            }
        }
    }
    Ok(Some(accepted))
}

/// Read one answer. A whole word is accepted as well as its first letter, since
/// people type `yes`; anything else — including an empty line — is a request for
/// the legend rather than a default, because every default here is wrong for
/// somebody.
fn answer_of(line: &str) -> Option<Answer> {
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Some(Answer::Yes),
        "n" | "no" => Some(Answer::No),
        "d" | "diff" => Some(Answer::Diff),
        "a" | "all" => Some(Answer::All),
        "s" | "stop" | "skip" => Some(Answer::Rest),
        "q" | "quit" => Some(Answer::Quit),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::file_digest;
    use crate::tree::{PathState, Stamp};

    /// An `Ask` that answers from a list, for driving [`choose`].
    struct Scripted {
        answers: std::collections::VecDeque<Answer>,
        shown: Vec<String>,
    }

    impl Ask for Scripted {
        fn ask(&mut self, _step: &Step, _position: usize, _total: usize) -> io::Result<Answer> {
            Ok(self
                .answers
                .pop_front()
                .expect("an answer for every question"))
        }

        fn note(&mut self, text: &str) -> io::Result<()> {
            self.shown.push(text.to_string());
            Ok(())
        }
    }

    fn scripted(answers: &[Answer]) -> Scripted {
        Scripted {
            answers: answers.iter().copied().collect(),
            shown: Vec::new(),
        }
    }

    fn plan_of(paths: &[(&str, PathState)]) -> Vec<Step> {
        paths
            .iter()
            .map(|(path, to)| Step {
                path: path.to_string(),
                from: PathState::Absent,
                to: to.clone(),
                mtime: Stamp::default(),
            })
            .collect()
    }

    /// A step that removes whatever is at `path`.
    fn gone(path: &str) -> Step {
        Step {
            path: path.to_string(),
            from: a_file(),
            to: PathState::Absent,
            mtime: Stamp::default(),
        }
    }

    fn a_file() -> PathState {
        PathState::File {
            digest: file_digest(b"x"),
            size: 1,
            mode: 0o644,
        }
    }

    #[test]
    fn declining_a_directory_declines_everything_inside_it() {
        let steps = plan_of(&[
            ("keep", PathState::Dir),
            ("keep/a.txt", a_file()),
            ("drop", PathState::Dir),
            ("drop/b.txt", a_file()),
            ("drop/deeper/c.txt", a_file()),
            ("after.txt", a_file()),
        ]);
        // Yes to `keep` and its file, no to `drop` — and then one more answer,
        // for `after.txt`, because nothing inside `drop` is ever asked about.
        let mut ask = scripted(&[Answer::Yes, Answer::Yes, Answer::No, Answer::Yes]);
        let mut untouched = Vec::new();
        let accepted = choose(
            steps,
            &mut ask,
            |_| unreachable!("no diff was asked for"),
            |step, why| untouched.push(format!("{}: {why}", step.path)),
        )
        .unwrap()
        .unwrap();

        let paths: Vec<&str> = accepted.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, ["keep", "keep/a.txt", "after.txt"]);
        assert_eq!(
            untouched,
            [
                "drop/b.txt: inside drop, left alone",
                "drop/deeper/c.txt: inside drop, left alone"
            ]
        );
    }

    #[test]
    fn keeping_a_file_keeps_the_directories_above_it() {
        // Deletions arrive children-first, so the answer that matters comes
        // before the directory it decides the fate of.
        let steps = vec![
            gone("doomed/keep.txt"),
            gone("doomed/go.txt"),
            gone("doomed"),
            gone("empty"),
        ];
        let mut ask = scripted(&[Answer::No, Answer::Yes, Answer::Yes]);
        let mut untouched = Vec::new();
        let accepted = choose(
            steps,
            &mut ask,
            |_| unreachable!(),
            |step, why| untouched.push(format!("{}: {why}", step.path)),
        )
        .unwrap()
        .unwrap();

        let paths: Vec<&str> = accepted.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, ["doomed/go.txt", "empty"]);
        assert_eq!(untouched, ["doomed: still holds doomed/keep.txt"]);
    }

    #[test]
    fn a_diff_is_shown_and_the_same_question_asked_again() {
        let steps = plan_of(&[("one.txt", a_file())]);
        let mut ask = scripted(&[Answer::Diff, Answer::Yes]);
        let accepted = choose(
            steps,
            &mut ask,
            |step| Ok(format!("what {} would become", step.path)),
            |_, _| {},
        )
        .unwrap()
        .unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(ask.shown, ["what one.txt would become"]);
    }

    #[test]
    fn stopping_keeps_what_was_accepted_and_abandoning_keeps_nothing() {
        let steps = plan_of(&[("one.txt", a_file()), ("two.txt", a_file())]);
        let accepted = choose(
            steps.clone(),
            &mut scripted(&[Answer::Yes, Answer::Rest]),
            |_| unreachable!(),
            |_, _| {},
        )
        .unwrap()
        .unwrap();
        assert_eq!(accepted.len(), 1);

        let abandoned = choose(
            steps.clone(),
            &mut scripted(&[Answer::Yes, Answer::Quit]),
            |_| unreachable!(),
            |_, _| {},
        )
        .unwrap();
        assert!(abandoned.is_none(), "a run abandoned halfway did something");

        // `a` takes the question away for everything left.
        let all = choose(
            steps,
            &mut scripted(&[Answer::All]),
            |_| unreachable!(),
            |_, _| {},
        )
        .unwrap()
        .unwrap();
        assert_eq!(all.len(), 2);
    }

    fn step() -> Step {
        Step {
            path: "notes.txt".to_string(),
            from: PathState::Absent,
            to: PathState::File {
                digest: file_digest(b"hello"),
                size: 5,
                mode: 0o644,
            },
            mtime: Stamp::default(),
        }
    }

    fn answers(keys: &str) -> (Vec<Answer>, String) {
        let mut out = Vec::new();
        let mut prompt = Prompt::new(io::Cursor::new(keys.to_string()), Vec::new());
        let step = step();
        for i in 0..keys.lines().count().max(1) {
            out.push(prompt.ask(&step, i + 1, 3).unwrap());
        }
        let written = String::from_utf8(prompt.output).unwrap();
        (out, written)
    }

    #[test]
    fn each_key_and_its_whole_word_mean_the_same_thing() {
        let (given, _) = answers("y\nn\nd\na\ns\nq\n");
        assert_eq!(
            given,
            [
                Answer::Yes,
                Answer::No,
                Answer::Diff,
                Answer::All,
                Answer::Rest,
                Answer::Quit
            ]
        );
        let (given, _) = answers("yes\nno\ndiff\nall\nstop\nquit\n");
        assert_eq!(
            given,
            [
                Answer::Yes,
                Answer::No,
                Answer::Diff,
                Answer::All,
                Answer::Rest,
                Answer::Quit
            ]
        );
    }

    #[test]
    fn anything_unrecognised_asks_again_rather_than_guessing() {
        // A stray return, a fat-fingered key, then a real answer.
        let mut prompt = Prompt::new(io::Cursor::new("\nz\nn\n".to_string()), Vec::new());
        assert_eq!(prompt.ask(&step(), 1, 1).unwrap(), Answer::No);
        let written = String::from_utf8(prompt.output).unwrap();
        // Asked three times over, and the legend shown each time it was needed.
        assert_eq!(written.matches("[y/n/d/a/s/q]").count(), 3);
        assert!(written.contains("d show the difference"));
    }

    #[test]
    fn a_closed_input_is_a_refusal_not_consent() {
        let mut prompt = Prompt::new(io::Cursor::new(String::new()), Vec::new());
        assert_eq!(prompt.ask(&step(), 1, 1).unwrap(), Answer::Quit);
    }

    #[test]
    fn the_question_says_what_the_change_is() {
        let (_, written) = answers("y\n");
        assert!(written.contains("new"), "{written}");
        assert!(written.contains("notes.txt"), "{written}");
        assert!(written.contains("(5B)"), "{written}");
        assert!(written.contains("[1/3]"), "{written}");
    }
}
