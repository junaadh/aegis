#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Metadata(String);

impl Metadata {
    pub fn empty() -> Self {
        Self("{}".to_owned())
    }

    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == "{}"
    }
}
