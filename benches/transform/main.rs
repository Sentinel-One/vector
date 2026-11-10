use criterion::criterion_main;

mod common;
mod condition;
mod dedupe;
mod filter;
mod reduce;
mod route;
mod route_branching;

criterion_main!(
    condition::benches,
    dedupe::benches,
    filter::benches,
    reduce::benches,
    route::benches,
    route_branching::benches,
);
