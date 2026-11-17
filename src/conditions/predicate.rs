use vector_lib::configurable::configurable_component;
use vrl::compiler::ProgramInfo;

use crate::conditions::{equality::Equality, Condition, ConditionalConfig};
use crate::event::Event;

/// A condition written as a tree of declarative operators (`all`, `any`, `not`, `eq`, `gt`, `cidr`
/// and so on) instead of a VRL expression.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PredicateConfig {
    /// The predicate an event must satisfy.
    pub when: vector_lib::predicate::PredicateConfig,
}

#[derive(Clone, Debug)]
pub struct Predicate {
    predicate: vector_lib::predicate::Predicate,
    pg_info: ProgramInfo,
}

impl Predicate {
    pub(crate) fn check(&self, e: Event) -> (bool, Event) {
        let (log_ns, target) = Equality::make_target(&self.pg_info, e);
        let matched = self.predicate.eval(&target);
        (matched, Equality::into_event(target, log_ns))
    }

    pub(crate) fn check_with_context(&self, e: Event) -> (Result<(), String>, Event) {
        let (matched, event) = self.check(e);
        let result = if matched {
            Ok(())
        } else {
            Err("predicate did not match".into())
        };
        (result, event)
    }
}

impl ConditionalConfig for PredicateConfig {
    fn build(
        &self,
        _enrichment_tables: &vector_lib::enrichment::TableRegistry,
    ) -> crate::Result<Condition> {
        let predicate = self.when.build()?;
        let pg_info = predicate.program_info();
        Ok(Condition::Predicate(Predicate { predicate, pg_info }))
    }
}

#[cfg(test)]
mod tests;
