use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResolutionError {
    #[error("cannot find module '{specifier}' from '{from}'")]
    NotFound { specifier: String, from: PathBuf },
}

/// Minimal placeholder resolver; the Node algorithm lands with the module track.
pub fn resolve(specifier: &str, from: &Path) -> Result<PathBuf, ResolutionError> {
    let candidate = from.parent().unwrap_or(Path::new(".")).join(specifier);
    if candidate.exists() {
        Ok(candidate)
    } else {
        Err(ResolutionError::NotFound {
            specifier: specifier.to_string(),
            from: from.to_path_buf(),
        })
    }
}
