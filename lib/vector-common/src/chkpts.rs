use std::{borrow::Cow, error::Error, fmt::Display};

use async_trait::async_trait;
use crate::id::ComponentKey;
use chrono::{DateTime, Utc};

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ChkptId {
    pub key: ComponentKey,
    pub id: String,
}

impl ChkptId {
    pub fn new(key: ComponentKey, id: String) -> Self {
        Self { key, id }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Value {
    pub chkpt: ChkptId,
    pub value: String,
    pub context: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ListEntry {
    pub id: String,
    pub updated_at: DateTime<Utc>,
    pub value: Option<String>,
}

#[derive(Debug)]
pub enum ChkptErr {
    NotFound(ChkptId),
    RaceLost(Value),
    TooBig(Value),
    Unknown(crate::Error)
}

impl Display for ChkptErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ChkptErr {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Unknown(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

#[async_trait]
pub trait Accessor: Send + dyn_clone::DynClone + Sync {
    async fn get(&self, id: Cow<'_, str>) -> Result<Value, ChkptErr>;
    async fn set(&self, id: Cow<'_, str>, value: Cow<'_, str>, ctx: Cow<'_, str>) -> Result<(), ChkptErr>;
    async fn compare_and_set(&self, id: Cow<'_, str>, value: Cow<'_, str>, if_old: Cow<'_, str>, ctx: Cow<'_, str>) -> Result<(), ChkptErr>;
    async fn del(&self, id: Cow<'_, str>) -> Result<(), ChkptErr>;
    async fn compare_and_del(&self, id: Cow<'_, str>, if_old: Cow<'_, str>) -> Result<(), ChkptErr>;
    async fn del_range(&self, from: Cow<'_, str>, to: Cow<'_, str>) -> Result<u64, ChkptErr>;
    async fn list_range(&self, from: Cow<'_, str>, to: Cow<'_, str>, limit: u32, with_values: bool) -> Result<Vec<ListEntry>, ChkptErr>;
}

dyn_clone::clone_trait_object!(Accessor);
