use asteria::{
    Engine,
    domain::{NewOrder, OrderIntent, OrderKind, Side, TimeInForce},
    engine::default_markets,
    store::StateStore,
};
use rust_decimal_macros::dec;

#[test]
fn restores_accounts_orders_and_event_chain_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.redb");
    let sequence;
    {
        let store = StateStore::open(&path).unwrap();
        let mut engine = Engine::open(store, default_markets()).unwrap();
        engine.credit_account("maker".into(), dec!(1000)).unwrap();
        engine
            .submit_order(NewOrder {
                account_id: "maker".into(),
                intent: OrderIntent {
                    client_order_id: "persisted-order".into(),
                    symbol: "BTCUSDT".into(),
                    side: Side::Sell,
                    kind: OrderKind::Limit,
                    quantity: dec!(0.01),
                    price: Some(dec!(60000)),
                    leverage: 10,
                    time_in_force: TimeInForce::Gtc,
                    reduce_only: false,
                },
            })
            .unwrap();
        sequence = engine.state().sequence;
        assert_eq!(engine.book("BTCUSDT", 20).unwrap().asks.len(), 1);
    }

    let store = StateStore::open(&path).unwrap();
    let engine = Engine::open(store, default_markets()).unwrap();
    assert_eq!(engine.state().sequence, sequence);
    assert_eq!(engine.book("BTCUSDT", 20).unwrap().asks.len(), 1);
    assert!(engine.account("maker").unwrap().reserved_margin > dec!(0));
    assert!(engine.audit().healthy, "{:?}", engine.audit().errors);
}
