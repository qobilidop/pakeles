impl serde::Serialize for Accepted {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.headers.is_empty() {
            len += 1;
        }
        if !self.metadata.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.testvec.v1alpha1.Accepted", len)?;
        if !self.headers.is_empty() {
            struct_ser.serialize_field("headers", &self.headers)?;
        }
        if !self.metadata.is_empty() {
            struct_ser.serialize_field("metadata", &self.metadata)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Accepted {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "headers",
            "metadata",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Headers,
            Metadata,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "headers" => Ok(GeneratedField::Headers),
                            "metadata" => Ok(GeneratedField::Metadata),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Accepted;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.testvec.v1alpha1.Accepted")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Accepted, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut headers__ = None;
                let mut metadata__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Headers => {
                            if headers__.is_some() {
                                return Err(serde::de::Error::duplicate_field("headers"));
                            }
                            headers__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Metadata => {
                            if metadata__.is_some() {
                                return Err(serde::de::Error::duplicate_field("metadata"));
                            }
                            metadata__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(Accepted {
                    headers: headers__.unwrap_or_default(),
                    metadata: metadata__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.testvec.v1alpha1.Accepted", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for BitString {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.data_hex.is_empty() {
            len += 1;
        }
        if self.bit_len != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.testvec.v1alpha1.BitString", len)?;
        if !self.data_hex.is_empty() {
            struct_ser.serialize_field("dataHex", &self.data_hex)?;
        }
        if self.bit_len != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("bitLen", ToString::to_string(&self.bit_len).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for BitString {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "data_hex",
            "dataHex",
            "bit_len",
            "bitLen",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            DataHex,
            BitLen,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "dataHex" | "data_hex" => Ok(GeneratedField::DataHex),
                            "bitLen" | "bit_len" => Ok(GeneratedField::BitLen),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = BitString;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.testvec.v1alpha1.BitString")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<BitString, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut data_hex__ = None;
                let mut bit_len__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::DataHex => {
                            if data_hex__.is_some() {
                                return Err(serde::de::Error::duplicate_field("dataHex"));
                            }
                            data_hex__ = Some(map_.next_value()?);
                        }
                        GeneratedField::BitLen => {
                            if bit_len__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bitLen"));
                            }
                            bit_len__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(BitString {
                    data_hex: data_hex__.unwrap_or_default(),
                    bit_len: bit_len__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.testvec.v1alpha1.BitString", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Category {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "CATEGORY_UNSPECIFIED",
            Self::Accept => "CATEGORY_ACCEPT",
            Self::Reject => "CATEGORY_REJECT",
            Self::Truncation => "CATEGORY_TRUNCATION",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for Category {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "CATEGORY_UNSPECIFIED",
            "CATEGORY_ACCEPT",
            "CATEGORY_REJECT",
            "CATEGORY_TRUNCATION",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Category;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                    })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v)
                    .ok()
                    .and_then(|x| x.try_into().ok())
                    .ok_or_else(|| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                    })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "CATEGORY_UNSPECIFIED" => Ok(Category::Unspecified),
                    "CATEGORY_ACCEPT" => Ok(Category::Accept),
                    "CATEGORY_REJECT" => Ok(Category::Reject),
                    "CATEGORY_TRUNCATION" => Ok(Category::Truncation),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for Expected {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.outcome.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.testvec.v1alpha1.Expected", len)?;
        if let Some(v) = self.outcome.as_ref() {
            match v {
                expected::Outcome::Accept(v) => {
                    struct_ser.serialize_field("accept", v)?;
                }
                expected::Outcome::Reject(v) => {
                    struct_ser.serialize_field("reject", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Expected {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "accept",
            "reject",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Accept,
            Reject,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "accept" => Ok(GeneratedField::Accept),
                            "reject" => Ok(GeneratedField::Reject),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Expected;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.testvec.v1alpha1.Expected")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Expected, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut outcome__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Accept => {
                            if outcome__.is_some() {
                                return Err(serde::de::Error::duplicate_field("accept"));
                            }
                            outcome__ = map_.next_value::<::std::option::Option<_>>()?.map(expected::Outcome::Accept)
;
                        }
                        GeneratedField::Reject => {
                            if outcome__.is_some() {
                                return Err(serde::de::Error::duplicate_field("reject"));
                            }
                            outcome__ = map_.next_value::<::std::option::Option<_>>()?.map(expected::Outcome::Reject)
;
                        }
                    }
                }
                Ok(Expected {
                    outcome: outcome__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.testvec.v1alpha1.Expected", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for ExpectedField {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.name.is_empty() {
            len += 1;
        }
        if self.value.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.testvec.v1alpha1.ExpectedField", len)?;
        if !self.name.is_empty() {
            struct_ser.serialize_field("name", &self.name)?;
        }
        if let Some(v) = self.value.as_ref() {
            match v {
                expected_field::Value::Uint(v) => {
                    #[allow(clippy::needless_borrow)]
                    #[allow(clippy::needless_borrows_for_generic_args)]
                    struct_ser.serialize_field("uint", ToString::to_string(&v).as_str())?;
                }
                expected_field::Value::Bits(v) => {
                    struct_ser.serialize_field("bits", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ExpectedField {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "name",
            "uint",
            "bits",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Name,
            Uint,
            Bits,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "name" => Ok(GeneratedField::Name),
                            "uint" => Ok(GeneratedField::Uint),
                            "bits" => Ok(GeneratedField::Bits),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ExpectedField;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.testvec.v1alpha1.ExpectedField")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<ExpectedField, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut name__ = None;
                let mut value__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Name => {
                            if name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Uint => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("uint"));
                            }
                            value__ = map_.next_value::<::std::option::Option<::pbjson::private::NumberDeserialize<_>>>()?.map(|x| expected_field::Value::Uint(x.0));
                        }
                        GeneratedField::Bits => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bits"));
                            }
                            value__ = map_.next_value::<::std::option::Option<_>>()?.map(expected_field::Value::Bits)
;
                        }
                    }
                }
                Ok(ExpectedField {
                    name: name__.unwrap_or_default(),
                    value: value__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.testvec.v1alpha1.ExpectedField", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for ExpectedHeader {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.instance.is_empty() {
            len += 1;
        }
        if !self.fields.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.testvec.v1alpha1.ExpectedHeader", len)?;
        if !self.instance.is_empty() {
            struct_ser.serialize_field("instance", &self.instance)?;
        }
        if !self.fields.is_empty() {
            struct_ser.serialize_field("fields", &self.fields)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ExpectedHeader {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "instance",
            "fields",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Instance,
            Fields,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "instance" => Ok(GeneratedField::Instance),
                            "fields" => Ok(GeneratedField::Fields),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ExpectedHeader;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.testvec.v1alpha1.ExpectedHeader")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<ExpectedHeader, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut instance__ = None;
                let mut fields__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Instance => {
                            if instance__.is_some() {
                                return Err(serde::de::Error::duplicate_field("instance"));
                            }
                            instance__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Fields => {
                            if fields__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fields"));
                            }
                            fields__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(ExpectedHeader {
                    instance: instance__.unwrap_or_default(),
                    fields: fields__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.testvec.v1alpha1.ExpectedHeader", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for ExpectedMeta {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.name.is_empty() {
            len += 1;
        }
        if self.value != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.testvec.v1alpha1.ExpectedMeta", len)?;
        if !self.name.is_empty() {
            struct_ser.serialize_field("name", &self.name)?;
        }
        if self.value != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("value", ToString::to_string(&self.value).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ExpectedMeta {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "name",
            "value",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Name,
            Value,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "name" => Ok(GeneratedField::Name),
                            "value" => Ok(GeneratedField::Value),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ExpectedMeta;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.testvec.v1alpha1.ExpectedMeta")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<ExpectedMeta, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut name__ = None;
                let mut value__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Name => {
                            if name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Value => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            value__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(ExpectedMeta {
                    name: name__.unwrap_or_default(),
                    value: value__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.testvec.v1alpha1.ExpectedMeta", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Rejected {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.reason.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.testvec.v1alpha1.Rejected", len)?;
        if !self.reason.is_empty() {
            struct_ser.serialize_field("reason", &self.reason)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Rejected {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "reason",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Reason,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "reason" => Ok(GeneratedField::Reason),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Rejected;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.testvec.v1alpha1.Rejected")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Rejected, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut reason__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Reason => {
                            if reason__.is_some() {
                                return Err(serde::de::Error::duplicate_field("reason"));
                            }
                            reason__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(Rejected {
                    reason: reason__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.testvec.v1alpha1.Rejected", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for TestSuite {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.parser_name.is_empty() {
            len += 1;
        }
        if !self.ir_version.is_empty() {
            len += 1;
        }
        if !self.vectors.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.testvec.v1alpha1.TestSuite", len)?;
        if !self.parser_name.is_empty() {
            struct_ser.serialize_field("parserName", &self.parser_name)?;
        }
        if !self.ir_version.is_empty() {
            struct_ser.serialize_field("irVersion", &self.ir_version)?;
        }
        if !self.vectors.is_empty() {
            struct_ser.serialize_field("vectors", &self.vectors)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TestSuite {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "parser_name",
            "parserName",
            "ir_version",
            "irVersion",
            "vectors",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            ParserName,
            IrVersion,
            Vectors,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "parserName" | "parser_name" => Ok(GeneratedField::ParserName),
                            "irVersion" | "ir_version" => Ok(GeneratedField::IrVersion),
                            "vectors" => Ok(GeneratedField::Vectors),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TestSuite;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.testvec.v1alpha1.TestSuite")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TestSuite, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut parser_name__ = None;
                let mut ir_version__ = None;
                let mut vectors__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::ParserName => {
                            if parser_name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("parserName"));
                            }
                            parser_name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::IrVersion => {
                            if ir_version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("irVersion"));
                            }
                            ir_version__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Vectors => {
                            if vectors__.is_some() {
                                return Err(serde::de::Error::duplicate_field("vectors"));
                            }
                            vectors__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(TestSuite {
                    parser_name: parser_name__.unwrap_or_default(),
                    ir_version: ir_version__.unwrap_or_default(),
                    vectors: vectors__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.testvec.v1alpha1.TestSuite", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for TestVector {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.id.is_empty() {
            len += 1;
        }
        if self.category != 0 {
            len += 1;
        }
        if self.packet.is_some() {
            len += 1;
        }
        if self.expected.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.testvec.v1alpha1.TestVector", len)?;
        if !self.id.is_empty() {
            struct_ser.serialize_field("id", &self.id)?;
        }
        if self.category != 0 {
            let v = Category::try_from(self.category)
                .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", self.category)))?;
            struct_ser.serialize_field("category", &v)?;
        }
        if let Some(v) = self.packet.as_ref() {
            struct_ser.serialize_field("packet", v)?;
        }
        if let Some(v) = self.expected.as_ref() {
            struct_ser.serialize_field("expected", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TestVector {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "id",
            "category",
            "packet",
            "expected",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Id,
            Category,
            Packet,
            Expected,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;

                impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
                    type Value = GeneratedField;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }

                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "id" => Ok(GeneratedField::Id),
                            "category" => Ok(GeneratedField::Category),
                            "packet" => Ok(GeneratedField::Packet),
                            "expected" => Ok(GeneratedField::Expected),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TestVector;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.testvec.v1alpha1.TestVector")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TestVector, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut id__ = None;
                let mut category__ = None;
                let mut packet__ = None;
                let mut expected__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Id => {
                            if id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("id"));
                            }
                            id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Category => {
                            if category__.is_some() {
                                return Err(serde::de::Error::duplicate_field("category"));
                            }
                            category__ = Some(map_.next_value::<Category>()? as i32);
                        }
                        GeneratedField::Packet => {
                            if packet__.is_some() {
                                return Err(serde::de::Error::duplicate_field("packet"));
                            }
                            packet__ = map_.next_value()?;
                        }
                        GeneratedField::Expected => {
                            if expected__.is_some() {
                                return Err(serde::de::Error::duplicate_field("expected"));
                            }
                            expected__ = map_.next_value()?;
                        }
                    }
                }
                Ok(TestVector {
                    id: id__.unwrap_or_default(),
                    category: category__.unwrap_or_default(),
                    packet: packet__,
                    expected: expected__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.testvec.v1alpha1.TestVector", FIELDS, GeneratedVisitor)
    }
}
