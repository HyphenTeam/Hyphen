use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasmparser::{ExternalKind, Parser, Payload};

pub const APP_MANIFEST_SECTION: &str = "hyphen.app";
pub const APP_ABI_VERSION: u16 = 1;
pub const APP_QUERY_EXPORT: &str = "hyphen_query";
pub const APP_EXECUTE_EXPORT: &str = "hyphen_execute";
const MAX_MANIFEST_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppCategory {
    Defi,
    Game,
    Utility,
}

impl std::fmt::Display for AppCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Defi => "defi",
            Self::Game => "game",
            Self::Utility => "utility",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppManifest {
    pub abi: u16,
    pub category: AppCategory,
    pub name: String,
    pub version: String,
}

impl AppManifest {
    fn validate(&self) -> Result<(), AppManifestError> {
        if self.abi != APP_ABI_VERSION {
            return Err(AppManifestError::UnsupportedAbi(self.abi));
        }
        if !valid_label(&self.name, 64) || !valid_label(&self.version, 32) {
            return Err(AppManifestError::InvalidLabel);
        }
        Ok(())
    }
}

fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'_' | b'-'))
}

pub fn application_manifest(code: &[u8]) -> Result<Option<AppManifest>, AppManifestError> {
    let mut manifest = None;
    let mut has_query = false;
    let mut has_execute = false;

    for payload in Parser::new(0).parse_all(code) {
        match payload.map_err(|error| AppManifestError::MalformedWasm(error.to_string()))? {
            Payload::CustomSection(section) if section.name() == APP_MANIFEST_SECTION => {
                if manifest.is_some() {
                    return Err(AppManifestError::DuplicateManifest);
                }
                if section.data().len() > MAX_MANIFEST_BYTES {
                    return Err(AppManifestError::ManifestTooLarge);
                }
                let parsed: AppManifest = serde_json::from_slice(section.data())
                    .map_err(|error| AppManifestError::MalformedManifest(error.to_string()))?;
                parsed.validate()?;
                manifest = Some(parsed);
            }
            Payload::ExportSection(exports) => {
                for export in exports {
                    let export = export
                        .map_err(|error| AppManifestError::MalformedWasm(error.to_string()))?;
                    if export.kind == ExternalKind::Func {
                        has_query |= export.name == APP_QUERY_EXPORT;
                        has_execute |= export.name == APP_EXECUTE_EXPORT;
                    }
                }
            }
            _ => {}
        }
    }

    if manifest.is_some() && (!has_query || !has_execute) {
        return Err(AppManifestError::MissingApplicationExports);
    }
    Ok(manifest)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AppManifestError {
    #[error("malformed WASM: {0}")]
    MalformedWasm(String),
    #[error("hyphen.app manifest exceeds {MAX_MANIFEST_BYTES} bytes")]
    ManifestTooLarge,
    #[error("contract contains more than one hyphen.app manifest")]
    DuplicateManifest,
    #[error("malformed hyphen.app manifest: {0}")]
    MalformedManifest(String),
    #[error("unsupported application ABI version {0}")]
    UnsupportedAbi(u16),
    #[error("application name or version is invalid")]
    InvalidLabel,
    #[error("application contracts must export hyphen_query and hyphen_execute")]
    MissingApplicationExports,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application_wasm(manifest: &str, exports: bool) -> Vec<u8> {
        let functions = if exports {
            r#"(func (export "hyphen_query")) (func (export "hyphen_execute"))"#
        } else {
            ""
        };
        wasmer::wat2wasm(
            format!(
                r#"(module (@custom "hyphen.app" "{manifest}") (memory (export "memory") 1 1) {functions})"#
            )
            .as_bytes(),
        )
        .unwrap()
        .into_owned()
    }

    #[test]
    fn parses_versioned_defi_manifest() {
        let code = application_wasm(
            r#"{\"abi\":1,\"category\":\"defi\",\"name\":\"Hyphen Swap\",\"version\":\"1.0.0\"}"#,
            true,
        );
        let manifest = application_manifest(&code).unwrap().unwrap();
        assert_eq!(manifest.category, AppCategory::Defi);
        assert_eq!(manifest.name, "Hyphen Swap");
    }

    #[test]
    fn manifest_requires_stable_exports() {
        let code = application_wasm(
            r#"{\"abi\":1,\"category\":\"game\",\"name\":\"Grid\",\"version\":\"1\"}"#,
            false,
        );
        assert_eq!(
            application_manifest(&code),
            Err(AppManifestError::MissingApplicationExports)
        );
    }
}
