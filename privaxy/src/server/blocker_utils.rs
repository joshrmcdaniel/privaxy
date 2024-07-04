//! Implementation of following utils are derived from https://raw.githubusercontent.com/brave/adblock-rust/master/src/resources/resource_assembler.rs
//! Contains methods useful for building `Resource` descriptors from resources directly from files
//! in the uBlock Origin repository.
use adblock::resources::{MimeType, PermissionMask, Resource, ResourceType};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;

static TOP_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^/\*[\S\s]+?\n\*/\s*"#).unwrap());
static NON_EMPTY_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\S"#).unwrap());

/// Represents a single entry of the `Map` from uBlock Origin's `redirect-resources.js`.
///
/// - `name` is the name of a resource, corresponding to its path in the `web_accessible_resources`
/// directory
///
/// - `alias` is a list of optional additional names that can be used to reference the resource
///
/// - `data` is either `"text"` or `"blob"`, but is currently unused in `adblock-rust`. Within
/// uBlock Origin, it's used to prevent text files from being encoded in base64 in a data URL.
pub struct ResourceProperties {
    pub name: String,
    pub alias: Vec<String>,
    #[allow(dead_code)]
    pub data: Option<String>,
}
use base64::{engine::general_purpose, Engine};

/// The deserializable represenation of the `alias` field of a resource's properties, which can
/// either be a single string or a list of strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum ResourceAliasField {
    SingleString(String),
    ListOfStrings(Vec<String>),
}

impl ResourceAliasField {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::SingleString(s) => vec![s],
            Self::ListOfStrings(l) => l,
        }
    }
}

/// Directly deserializable representation of a resource's properties from `redirect-resources.js`.
#[derive(serde::Deserialize)]
struct JsResourceProperties {
    #[serde(default)]
    alias: Option<ResourceAliasField>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    params: Option<Vec<String>>,
}

/// Maps the name of the resource to its properties in a 2-element tuple.
type JsResourceEntry = (String, JsResourceProperties);

const REDIRECTABLE_RESOURCES_DECLARATION: &str = "export default new Map([";
//  ]);
static MAP_END_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\s*\]\s*\)"#).unwrap());
static TRAILING_COMMA_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#",([\],\}])"#).unwrap());
static UNQUOTED_FIELD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"([\{,])([a-zA-Z][a-zA-Z0-9_]*):"#).unwrap());

/// Reads data from a a file in the format of uBlock Origin's `redirect-resources.js` file to
/// determine the files in the `web_accessible_resources` directory, as well as any of their
/// aliases.
///
/// This is read from the exported `Map`.
pub fn read_redirectable_resource_mapping(mapfile_data: &str) -> Vec<ResourceProperties> {
    // This isn't bulletproof, but it should handle the historical versions of the mapping
    // correctly, and having a strict JSON parser should catch any unexpected format changes. Plus,
    // it prevents dependending on a full JS engine.

    // Extract just the map. It's between REDIRECTABLE_RESOURCES_DECLARATION and MAP_END_RE.
    let mut map: String = mapfile_data
        .lines()
        .skip_while(|line| *line != REDIRECTABLE_RESOURCES_DECLARATION)
        .take_while(|line| !MAP_END_RE.is_match(line))
        // Strip any trailing comments from each line.
        .map(|line| line.split("//").next().unwrap_or("").trim())
        // Remove all newlines from the entire string.
        .collect::<String>();

    // Add back the final square brace that was omitted above as part of MAP_END_RE.
    map.push(']');

    // Trim out the beginning `export default new Map(`.
    // Also, replace all single quote characters with double quotes.
    assert!(map.starts_with(REDIRECTABLE_RESOURCES_DECLARATION));
    map = map[REDIRECTABLE_RESOURCES_DECLARATION.len() - 1..].replace('\'', "\"");

    // Remove all whitespace from the entire string.
    map.retain(|c| !c.is_whitespace());

    // Replace all matches for `,]` or `,}` with `]` or `}`, respectively.
    map = TRAILING_COMMA_RE.replace_all(&map, "$1").to_string();
    // Replace all property keys directly preceded by a `{` or a `,` and followed by a `:` with
    // double-quoted versions.
    map = UNQUOTED_FIELD_RE
        .replace_all(&map, r#"$1"$2":"#)
        .to_string();

    // It *should* be valid JSON now, so parse it with serde_json.
    let parsed: Vec<JsResourceEntry> = serde_json::from_str(&map).unwrap();

    parsed
        .into_iter()
        .filter_map(|(name, props)| {
            // Ignore resources with params for now, since there's no support for them currently.
            if props.params.is_some() {
                None
            } else {
                Some(ResourceProperties {
                    name,
                    alias: props.alias.map(|a| a.into_vec()).unwrap_or_default(),
                    data: props.data,
                })
            }
        })
        .collect()
}

/// Reads data from a file in the form of uBlock Origin's `scriptlets.js` file and produces
/// templatable scriptlets for use in cosmetic filtering.
pub fn read_template_resources(scriptlets_data: &str) -> Vec<Resource> {
    let mut resources = Vec::new();

    let uncommented = TOP_COMMENT_RE.replace_all(scriptlets_data, "");
    let mut name: Option<&str> = None;
    let mut details = std::collections::HashMap::<_, Vec<_>>::new();
    let mut script = String::new();

    for line in uncommented.lines() {
        if line.starts_with('#') || line.starts_with("// ") || line == "//" {
            continue;
        }

        if name.is_none() {
            if let Some(stripped) = line.strip_prefix("/// ") {
                name = Some(stripped.trim());
            }
            continue;
        }

        if let Some(stripped) = line.strip_prefix("/// ") {
            let mut line_parts = stripped.split_whitespace();
            let prop = line_parts.next().expect("Detail line has property name");
            let value = line_parts.next().expect("Detail line has property value");
            details.entry(prop).or_default().push(value);
            continue;
        }

        if NON_EMPTY_LINE_RE.is_match(line) {
            script.push_str(line.trim());
            script.push('\n');
            continue;
        }

        let kind = if script.contains("{{1}}") {
            ResourceType::Template
        } else {
            ResourceType::Mime(MimeType::ApplicationJavascript)
        };

        resources.push(Resource {
            name: name.expect("Resource name must be specified").to_owned(),
            aliases: details
                .remove("alias")
                .unwrap_or_default()
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            kind,
            content: general_purpose::STANDARD.encode(&script),
            dependencies: Vec::new(),
            permission: PermissionMask::default(),
        });

        name = None;
        details.clear();
        script.clear();
    }

    resources
}

/// Reads byte data from an arbitrary resource file, and assembles a `Resource` from it with the
/// provided `resource_info`.
pub fn build_resource_from_file_contents(
    resource_contents: &[u8],
    resource_info: &ResourceProperties,
) -> Resource {
    let name = resource_info.name.clone();
    let aliases = resource_info.alias.clone();
    let mimetype = MimeType::from_extension(&resource_info.name);
    let content = match mimetype {
        MimeType::ApplicationJavascript | MimeType::TextHtml | MimeType::TextPlain => {
            let utf8string = std::str::from_utf8(resource_contents).unwrap();
            general_purpose::STANDARD.encode(utf8string.replace('\r', ""))
        }
        _ => general_purpose::STANDARD.encode(resource_contents),
    };

    Resource {
        name,
        aliases,
        kind: ResourceType::Mime(mimetype),
        content,
        dependencies: Vec::new(),
        permission: PermissionMask::default(),
    }
}
