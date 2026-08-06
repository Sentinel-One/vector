use mlua::prelude::*;

use super::super::{EventMetadata, LogEvent, ObjectMap, Value};
use super::util::{table_is_timestamp, table_to_timestamp};

impl IntoLua for LogEvent {
    #![allow(clippy::wrong_self_convention)] // this trait is defined by mlua
    fn into_lua(self, lua: &Lua) -> LuaResult<LuaValue> {
        let (value, _metadata) = self.into_parts();
        value.into_lua(lua)
    }
}

impl FromLua for LogEvent {
    fn from_lua(lua_value: LuaValue, lua: &Lua) -> LuaResult<Self> {
        let value = lua_table_to_vrl_value(lua_value, lua)?;
        Ok(LogEvent::from_parts(value, EventMetadata::default()))
    }
}

// Depth-safe replacement for Value::from_lua for table values.
//
// mlua's TableSequence::next() (used by Vec<Value>::from_lua) calls check_stack(1) but
// needs 3 slots: push_ref (+1) + lua_rawgeti (+1) + lua_pushvalue inside from_stack (+1).
// At 7+ levels of nesting the main Lua thread's ci->top (initial budget: LUA_MINSTACK=20)
// is exhausted and lua_pushvalue aborts with:
//   Assertion failed: (L->top.p <= L->ci->top.p), function lua_pushvalue, file lapi.c:273
//
// Table::for_each_value calls check_stack(4) for the whole traversal; Table::for_each
// calls check_stack(5) — both are sufficient and grow ci->top as recursion deepens.
fn lua_table_to_vrl_value(lua_value: LuaValue, lua: &Lua) -> LuaResult<Value> {
    match lua_value {
        LuaValue::Table(t) => {
            if t.len()? > 0 {
                let mut arr = Vec::new();
                t.for_each_value::<LuaValue>(|v| {
                    arr.push(lua_table_to_vrl_value(v, lua)?);
                    Ok(())
                })?;
                Ok(Value::Array(arr))
            } else if table_is_timestamp(&t)? {
                table_to_timestamp(t).map(Value::Timestamp)
            } else {
                let mut map = ObjectMap::new();
                t.for_each::<LuaValue, LuaValue>(|k, v| {
                    let key = match k {
                        LuaValue::String(s) => s.to_str()?.as_ref().into(),
                        LuaValue::Integer(i) => i.to_string().into(),
                        other => {
                            return Err(LuaError::FromLuaConversionError {
                                from: other.type_name(),
                                to: "KeyString".into(),
                                message: None,
                            })
                        }
                    };
                    map.insert(key, lua_table_to_vrl_value(v, lua)?);
                    Ok(())
                })?;
                Ok(Value::Object(map))
            }
        }
        other => Value::from_lua(other, lua),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn into_lua() {
        let mut log = LogEvent::default();
        log.insert("a", 1);
        log.insert("nested.field", "2");
        log.insert("nested.array[0]", "example value");
        log.insert("nested.array[2]", "another value");

        let assertions = vec![
            "type(log) == 'table'",
            "log.a == 1",
            "type(log.nested) == 'table'",
            "log.nested.field == '2'",
            "#log.nested.array == 3",
            "log.nested.array[1] == 'example value'",
            "log.nested.array[2] == ''",
            "log.nested.array[3] == 'another value'",
        ];

        let lua = Lua::new();
        lua.globals().set("log", log.clone()).unwrap();
        for assertion in assertions {
            let result: bool = lua
                .load(assertion)
                .eval()
                .unwrap_or_else(|_| panic!("Failed to verify assertion {assertion:?}"));
            assert!(result, "{}", assertion);
        }
    }

    #[test]
    fn from_lua() {
        let lua_event = r"
        {
            a = 1,
            nested = {
                field = '2',
                array = {'example value', '', 'another value'}
            }
        }
        ";

        let event: LogEvent = Lua::new().load(lua_event).eval().unwrap();

        assert_eq!(event["a"], Value::Integer(1));
        assert_eq!(event["nested.field"], Value::Bytes("2".into()));
        assert_eq!(
            event["nested.array[0]"],
            Value::Bytes("example value".into())
        );
        assert_eq!(event["nested.array[1]"], Value::Bytes("".into()));
        assert_eq!(
            event["nested.array[2]"],
            Value::Bytes("another value".into())
        );
    }

    // Regression test for mlua TableSequence::next() stack underallocation.
    // check_stack(1) is insufficient: push_ref+rawgeti+lua_pushvalue needs 3 slots.
    // With LUA_MINSTACK=20 and 3 slots/BTreeMap depth, 6 object levels + 1 array +
    // 1 object element exhausts ci->top and aborts inside lua_pushvalue.
    #[test]
    fn from_lua_deep_nesting_with_array() {
        let lua_event = r"
        {
            l1 = {
                l2 = {
                    l3 = {
                        l4 = {
                            l5 = {
                                l6 = {
                                    arr = {
                                        { leaf = 'value' }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        ";

        let event: LogEvent = Lua::new().load(lua_event).eval().unwrap();
        assert_eq!(
            event["l1.l2.l3.l4.l5.l6.arr[0].leaf"],
            Value::Bytes("value".into())
        );
    }
}
