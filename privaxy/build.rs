use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("cargo provides OUT_DIR"));

    build_procedural_shim(&manifest_dir, &out_dir);
    build_scriptlet_resources(&manifest_dir, &out_dir);
}

/// Strip the comments out of the procedural-cosmetics shim before it is embedded.
///
/// The shim is injected inline into every HTML response that has cosmetic rules,
/// and the proxy re-sends responses uncompressed, so its comments would be real
/// bytes on the wire on every page load — roughly two thirds of the file. Keeping
/// them in the source and dropping them here means the reasoning lives next to
/// the code without being paid for at runtime.
///
/// Deliberately not done with Node: the cross-compile path in
/// `build_scriptlet_resources` exists precisely because Node isn't always
/// available, and the shim has to be embedded in every build.
fn build_procedural_shim(manifest_dir: &Path, out_dir: &Path) {
    let source_path = manifest_dir.join("src/resources/procedural_cosmetics.js");
    println!("cargo:rerun-if-changed={}", source_path.display());

    let source = std::fs::read_to_string(&source_path).unwrap_or_else(|e| {
        panic!(
            "failed to read the procedural shim at {}: {e}",
            source_path.display()
        )
    });

    let embedded = match strip_whole_line_comments(&source) {
        Some(stripped) => stripped,
        None => {
            // Embedding the file verbatim is always correct, only larger, so an
            // unrecognised construct degrades instead of risking a corrupted shim
            // on every page.
            println!(
                "cargo:warning=procedural_cosmetics.js contains a construct the comment \
                 stripper does not handle (a multi-line string, or a comment sharing a line \
                 with code); embedding it verbatim. See strip_whole_line_comments in \
                 privaxy/build.rs."
            );
            source
        }
    };

    std::fs::write(out_dir.join("procedural_cosmetics.js"), embedded)
        .expect("failed to write the stripped procedural shim to OUT_DIR");
}

/// Remove comment-only lines, blank lines, and indentation from JavaScript.
///
/// This is a line-oriented pass, not a JavaScript lexer: it decides what to drop
/// purely from how a line *starts*, and never inspects the interior of a line it
/// keeps. That is what makes it safe without parsing — a `//` inside a string or
/// a regex literal cannot be mistaken for a comment, because such a line is kept
/// whole.
///
/// It returns `None` rather than guessing whenever it meets something that would
/// invalidate that reasoning:
///
///   * a backtick, which may open a template literal spanning lines: a line
///     inside one could begin with `//` and would then be dropped wrongly;
///   * a trailing backslash, i.e. a string continued onto the next line, for the
///     same reason;
///   * a comment sharing a line with code, where telling comment from string
///     genuinely does need a lexer.
///
/// Line numbers shift, which costs nothing here: the shim is concatenated after
/// the scriptlet payload before injection, so they never matched the file anyway.
fn strip_whole_line_comments(source: &str) -> Option<String> {
    let mut out = String::with_capacity(source.len());
    let mut in_block_comment = false;

    for line in source.lines() {
        let trimmed = line.trim();

        if in_block_comment {
            match trimmed.find("*/") {
                // Code trailing the end of a block comment needs a lexer to split.
                Some(end) if end + 2 != trimmed.len() => return None,
                Some(_) => in_block_comment = false,
                None => {}
            }
            continue;
        }

        if trimmed.starts_with("//") {
            continue;
        }

        if trimmed.starts_with("/*") {
            match trimmed.find("*/") {
                Some(end) if end + 2 != trimmed.len() => return None,
                // `/*/` both starts and ends with a delimiter without being a
                // complete comment, hence the length check.
                Some(_) if trimmed.len() >= 4 => {}
                _ => in_block_comment = true,
            }
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }

        if trimmed.contains('`')
            || trimmed.ends_with('\\')
            || trimmed.contains("//")
            || trimmed.contains("/*")
        {
            return None;
        }

        out.push_str(trimmed);
        out.push('\n');
    }

    // An unterminated block comment means the file was not what we assumed.
    if in_block_comment {
        return None;
    }

    Some(out)
}

fn build_scriptlet_resources(manifest_dir: &Path, out_dir: &Path) {
    let scriptlets_src = manifest_dir.join("src/resources/vendor/ublock/scriptlets.js");
    let builder = manifest_dir.join("build-scriptlets.mjs");
    let out_path = out_dir.join("scriptlets-resources.json");

    println!("cargo:rerun-if-changed={}", scriptlets_src.display());
    println!("cargo:rerun-if-changed={}", builder.display());

    // Allow cross-compile environments without Node (e.g. the cross-rs MIPS
    // container) to skip the Node preprocessing step by dropping a pre-built
    // JSON at a known workspace-relative path. CI generates this artifact in
    // the host-side build_frontend job and downloads it before cross-building.
    let prebuilt = manifest_dir.join("prebuilt/scriptlets-resources.json");
    println!("cargo:rerun-if-changed={}", prebuilt.display());
    if prebuilt.exists() {
        std::fs::copy(&prebuilt, &out_path).unwrap_or_else(|e| {
            panic!(
                "failed to copy prebuilt scriptlets from {}: {e}",
                prebuilt.display()
            )
        });
        return;
    }

    let status = Command::new("node")
        .arg(&builder)
        .arg(&scriptlets_src)
        .arg(&out_path)
        .status()
        .expect("failed to invoke `node` for scriptlet preprocessing — is Node.js installed and on PATH?");

    if !status.success() {
        panic!(
            "build-scriptlets.mjs exited with non-zero status: {:?}",
            status
        );
    }
}
