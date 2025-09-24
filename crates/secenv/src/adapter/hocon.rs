use {
    serde::de::{self, Deserializer, MapAccess, Visitor},
    std::fmt,
};

pub trait HoconEnum: Sized {
    fn deserialize_from_map<'de, M>(variant_name: &str, map: M) -> Result<Self, M::Error>
    where
        M: MapAccess<'de>;
}

pub fn deserialize_hocon_enum<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: HoconEnum,
{
    struct HoconEnumVisitor<T> {
        _phantom: std::marker::PhantomData<T>,
    }

    impl<'de, T: HoconEnum> Visitor<'de> for HoconEnumVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a HOCON enum object")
        }

        fn visit_map<M>(self, mut map: M) -> Result<T, M::Error>
        where
            M: MapAccess<'de>,
        {
            if let Some(variant_name) = map.next_key::<String>()? {
                T::deserialize_from_map(&variant_name, map)
            } else {
                Err(de::Error::custom("expected enum variant"))
            }
        }
    }

    deserializer.deserialize_map(HoconEnumVisitor {
        _phantom: std::marker::PhantomData,
    })
}
