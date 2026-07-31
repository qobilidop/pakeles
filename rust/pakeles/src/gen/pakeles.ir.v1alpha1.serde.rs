impl serde::Serialize for Accept {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let len = 0;
        let struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Accept", len)?;
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Accept {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
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
                            Err(serde::de::Error::unknown_field(value, FIELDS))
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Accept;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Accept")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Accept, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                while map_.next_key::<GeneratedField>()?.is_some() {
                    let _ = map_.next_value::<serde::de::IgnoredAny>()?;
                }
                Ok(Accept {
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Accept", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Assign {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.metadata.is_empty() {
            len += 1;
        }
        if self.value.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Assign", len)?;
        if !self.metadata.is_empty() {
            struct_ser.serialize_field("metadata", &self.metadata)?;
        }
        if let Some(v) = self.value.as_ref() {
            struct_ser.serialize_field("value", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Assign {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "metadata",
            "value",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Metadata,
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
                            "metadata" => Ok(GeneratedField::Metadata),
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
            type Value = Assign;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Assign")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Assign, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut metadata__ = None;
                let mut value__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Metadata => {
                            if metadata__.is_some() {
                                return Err(serde::de::Error::duplicate_field("metadata"));
                            }
                            metadata__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Value => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            value__ = map_.next_value()?;
                        }
                    }
                }
                Ok(Assign {
                    metadata: metadata__.unwrap_or_default(),
                    value: value__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Assign", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for BinOp {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.op != 0 {
            len += 1;
        }
        if self.lhs.is_some() {
            len += 1;
        }
        if self.rhs.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.BinOp", len)?;
        if self.op != 0 {
            let v = BinOpKind::try_from(self.op)
                .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", self.op)))?;
            struct_ser.serialize_field("op", &v)?;
        }
        if let Some(v) = self.lhs.as_ref() {
            struct_ser.serialize_field("lhs", v)?;
        }
        if let Some(v) = self.rhs.as_ref() {
            struct_ser.serialize_field("rhs", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for BinOp {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "op",
            "lhs",
            "rhs",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Op,
            Lhs,
            Rhs,
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
                            "op" => Ok(GeneratedField::Op),
                            "lhs" => Ok(GeneratedField::Lhs),
                            "rhs" => Ok(GeneratedField::Rhs),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = BinOp;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.BinOp")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<BinOp, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut op__ = None;
                let mut lhs__ = None;
                let mut rhs__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Op => {
                            if op__.is_some() {
                                return Err(serde::de::Error::duplicate_field("op"));
                            }
                            op__ = Some(map_.next_value::<BinOpKind>()? as i32);
                        }
                        GeneratedField::Lhs => {
                            if lhs__.is_some() {
                                return Err(serde::de::Error::duplicate_field("lhs"));
                            }
                            lhs__ = map_.next_value()?;
                        }
                        GeneratedField::Rhs => {
                            if rhs__.is_some() {
                                return Err(serde::de::Error::duplicate_field("rhs"));
                            }
                            rhs__ = map_.next_value()?;
                        }
                    }
                }
                Ok(BinOp {
                    op: op__.unwrap_or_default(),
                    lhs: lhs__,
                    rhs: rhs__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.BinOp", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for BinOpKind {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "BIN_OP_KIND_UNSPECIFIED",
            Self::Add => "BIN_OP_KIND_ADD",
            Self::Sub => "BIN_OP_KIND_SUB",
            Self::Mul => "BIN_OP_KIND_MUL",
            Self::Shl => "BIN_OP_KIND_SHL",
            Self::Shr => "BIN_OP_KIND_SHR",
            Self::And => "BIN_OP_KIND_AND",
            Self::Or => "BIN_OP_KIND_OR",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for BinOpKind {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "BIN_OP_KIND_UNSPECIFIED",
            "BIN_OP_KIND_ADD",
            "BIN_OP_KIND_SUB",
            "BIN_OP_KIND_MUL",
            "BIN_OP_KIND_SHL",
            "BIN_OP_KIND_SHR",
            "BIN_OP_KIND_AND",
            "BIN_OP_KIND_OR",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = BinOpKind;

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
                    "BIN_OP_KIND_UNSPECIFIED" => Ok(BinOpKind::Unspecified),
                    "BIN_OP_KIND_ADD" => Ok(BinOpKind::Add),
                    "BIN_OP_KIND_SUB" => Ok(BinOpKind::Sub),
                    "BIN_OP_KIND_MUL" => Ok(BinOpKind::Mul),
                    "BIN_OP_KIND_SHL" => Ok(BinOpKind::Shl),
                    "BIN_OP_KIND_SHR" => Ok(BinOpKind::Shr),
                    "BIN_OP_KIND_AND" => Ok(BinOpKind::And),
                    "BIN_OP_KIND_OR" => Ok(BinOpKind::Or),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for Display {
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
        if self.format != 0 {
            len += 1;
        }
        if !self.value_labels.is_empty() {
            len += 1;
        }
        if !self.doc.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Display", len)?;
        if !self.name.is_empty() {
            struct_ser.serialize_field("name", &self.name)?;
        }
        if self.format != 0 {
            let v = DisplayFormat::try_from(self.format)
                .map_err(|_| serde::ser::Error::custom(format!("Invalid variant {}", self.format)))?;
            struct_ser.serialize_field("format", &v)?;
        }
        if !self.value_labels.is_empty() {
            struct_ser.serialize_field("valueLabels", &self.value_labels)?;
        }
        if !self.doc.is_empty() {
            struct_ser.serialize_field("doc", &self.doc)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Display {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "name",
            "format",
            "value_labels",
            "valueLabels",
            "doc",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Name,
            Format,
            ValueLabels,
            Doc,
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
                            "format" => Ok(GeneratedField::Format),
                            "valueLabels" | "value_labels" => Ok(GeneratedField::ValueLabels),
                            "doc" => Ok(GeneratedField::Doc),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Display;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Display")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Display, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut name__ = None;
                let mut format__ = None;
                let mut value_labels__ = None;
                let mut doc__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Name => {
                            if name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Format => {
                            if format__.is_some() {
                                return Err(serde::de::Error::duplicate_field("format"));
                            }
                            format__ = Some(map_.next_value::<DisplayFormat>()? as i32);
                        }
                        GeneratedField::ValueLabels => {
                            if value_labels__.is_some() {
                                return Err(serde::de::Error::duplicate_field("valueLabels"));
                            }
                            value_labels__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Doc => {
                            if doc__.is_some() {
                                return Err(serde::de::Error::duplicate_field("doc"));
                            }
                            doc__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(Display {
                    name: name__.unwrap_or_default(),
                    format: format__.unwrap_or_default(),
                    value_labels: value_labels__.unwrap_or_default(),
                    doc: doc__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Display", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for DisplayFormat {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::Unspecified => "DISPLAY_FORMAT_UNSPECIFIED",
            Self::Dec => "DISPLAY_FORMAT_DEC",
            Self::Hex => "DISPLAY_FORMAT_HEX",
            Self::Bin => "DISPLAY_FORMAT_BIN",
            Self::Ipv4 => "DISPLAY_FORMAT_IPV4",
            Self::Ipv6 => "DISPLAY_FORMAT_IPV6",
            Self::Ether => "DISPLAY_FORMAT_ETHER",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for DisplayFormat {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "DISPLAY_FORMAT_UNSPECIFIED",
            "DISPLAY_FORMAT_DEC",
            "DISPLAY_FORMAT_HEX",
            "DISPLAY_FORMAT_BIN",
            "DISPLAY_FORMAT_IPV4",
            "DISPLAY_FORMAT_IPV6",
            "DISPLAY_FORMAT_ETHER",
        ];

        struct GeneratedVisitor;

        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = DisplayFormat;

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
                    "DISPLAY_FORMAT_UNSPECIFIED" => Ok(DisplayFormat::Unspecified),
                    "DISPLAY_FORMAT_DEC" => Ok(DisplayFormat::Dec),
                    "DISPLAY_FORMAT_HEX" => Ok(DisplayFormat::Hex),
                    "DISPLAY_FORMAT_BIN" => Ok(DisplayFormat::Bin),
                    "DISPLAY_FORMAT_IPV4" => Ok(DisplayFormat::Ipv4),
                    "DISPLAY_FORMAT_IPV6" => Ok(DisplayFormat::Ipv6),
                    "DISPLAY_FORMAT_ETHER" => Ok(DisplayFormat::Ether),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}
impl serde::Serialize for Expr {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.kind.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Expr", len)?;
        if let Some(v) = self.kind.as_ref() {
            match v {
                expr::Kind::Constant(v) => {
                    #[allow(clippy::needless_borrow)]
                    #[allow(clippy::needless_borrows_for_generic_args)]
                    struct_ser.serialize_field("constant", ToString::to_string(&v).as_str())?;
                }
                expr::Kind::Field(v) => {
                    struct_ser.serialize_field("field", v)?;
                }
                expr::Kind::Bin(v) => {
                    struct_ser.serialize_field("bin", v)?;
                }
                expr::Kind::Metadata(v) => {
                    struct_ser.serialize_field("metadata", v)?;
                }
                expr::Kind::Remaining(v) => {
                    struct_ser.serialize_field("remaining", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Expr {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "constant",
            "field",
            "bin",
            "metadata",
            "remaining",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Constant,
            Field,
            Bin,
            Metadata,
            Remaining,
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
                            "constant" => Ok(GeneratedField::Constant),
                            "field" => Ok(GeneratedField::Field),
                            "bin" => Ok(GeneratedField::Bin),
                            "metadata" => Ok(GeneratedField::Metadata),
                            "remaining" => Ok(GeneratedField::Remaining),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Expr;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Expr")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Expr, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut kind__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Constant => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("constant"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<::pbjson::private::NumberDeserialize<_>>>()?.map(|x| expr::Kind::Constant(x.0));
                        }
                        GeneratedField::Field => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("field"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(expr::Kind::Field)
;
                        }
                        GeneratedField::Bin => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bin"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(expr::Kind::Bin)
;
                        }
                        GeneratedField::Metadata => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("metadata"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(expr::Kind::Metadata)
;
                        }
                        GeneratedField::Remaining => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("remaining"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(expr::Kind::Remaining)
;
                        }
                    }
                }
                Ok(Expr {
                    kind: kind__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Expr", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Extract {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.header_type.is_empty() {
            len += 1;
        }
        if !self.instance.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Extract", len)?;
        if !self.header_type.is_empty() {
            struct_ser.serialize_field("headerType", &self.header_type)?;
        }
        if !self.instance.is_empty() {
            struct_ser.serialize_field("instance", &self.instance)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Extract {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "header_type",
            "headerType",
            "instance",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            HeaderType,
            Instance,
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
                            "headerType" | "header_type" => Ok(GeneratedField::HeaderType),
                            "instance" => Ok(GeneratedField::Instance),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Extract;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Extract")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Extract, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut header_type__ = None;
                let mut instance__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::HeaderType => {
                            if header_type__.is_some() {
                                return Err(serde::de::Error::duplicate_field("headerType"));
                            }
                            header_type__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Instance => {
                            if instance__.is_some() {
                                return Err(serde::de::Error::duplicate_field("instance"));
                            }
                            instance__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(Extract {
                    header_type: header_type__.unwrap_or_default(),
                    instance: instance__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Extract", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Field {
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
        if self.width.is_some() {
            len += 1;
        }
        if self.display.is_some() {
            len += 1;
        }
        if !self.annotations.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Field", len)?;
        if !self.name.is_empty() {
            struct_ser.serialize_field("name", &self.name)?;
        }
        if let Some(v) = self.width.as_ref() {
            struct_ser.serialize_field("width", v)?;
        }
        if let Some(v) = self.display.as_ref() {
            struct_ser.serialize_field("display", v)?;
        }
        if !self.annotations.is_empty() {
            struct_ser.serialize_field("annotations", &self.annotations)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Field {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "name",
            "width",
            "display",
            "annotations",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Name,
            Width,
            Display,
            Annotations,
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
                            "width" => Ok(GeneratedField::Width),
                            "display" => Ok(GeneratedField::Display),
                            "annotations" => Ok(GeneratedField::Annotations),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Field;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Field")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Field, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut name__ = None;
                let mut width__ = None;
                let mut display__ = None;
                let mut annotations__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Name => {
                            if name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Width => {
                            if width__.is_some() {
                                return Err(serde::de::Error::duplicate_field("width"));
                            }
                            width__ = map_.next_value()?;
                        }
                        GeneratedField::Display => {
                            if display__.is_some() {
                                return Err(serde::de::Error::duplicate_field("display"));
                            }
                            display__ = map_.next_value()?;
                        }
                        GeneratedField::Annotations => {
                            if annotations__.is_some() {
                                return Err(serde::de::Error::duplicate_field("annotations"));
                            }
                            annotations__ = Some(
                                map_.next_value::<std::collections::BTreeMap<_, _>>()?
                            );
                        }
                    }
                }
                Ok(Field {
                    name: name__.unwrap_or_default(),
                    width: width__,
                    display: display__,
                    annotations: annotations__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Field", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for FieldRef {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.header.is_empty() {
            len += 1;
        }
        if !self.field.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.FieldRef", len)?;
        if !self.header.is_empty() {
            struct_ser.serialize_field("header", &self.header)?;
        }
        if !self.field.is_empty() {
            struct_ser.serialize_field("field", &self.field)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for FieldRef {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "header",
            "field",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Header,
            Field,
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
                            "header" => Ok(GeneratedField::Header),
                            "field" => Ok(GeneratedField::Field),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = FieldRef;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.FieldRef")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<FieldRef, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut header__ = None;
                let mut field__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Header => {
                            if header__.is_some() {
                                return Err(serde::de::Error::duplicate_field("header"));
                            }
                            header__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Field => {
                            if field__.is_some() {
                                return Err(serde::de::Error::duplicate_field("field"));
                            }
                            field__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(FieldRef {
                    header: header__.unwrap_or_default(),
                    field: field__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.FieldRef", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for FieldWidth {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.width.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.FieldWidth", len)?;
        if let Some(v) = self.width.as_ref() {
            match v {
                field_width::Width::Bits(v) => {
                    struct_ser.serialize_field("bits", v)?;
                }
                field_width::Width::ByteLen(v) => {
                    struct_ser.serialize_field("byteLen", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for FieldWidth {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "bits",
            "byte_len",
            "byteLen",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Bits,
            ByteLen,
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
                            "bits" => Ok(GeneratedField::Bits),
                            "byteLen" | "byte_len" => Ok(GeneratedField::ByteLen),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = FieldWidth;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.FieldWidth")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<FieldWidth, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut width__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Bits => {
                            if width__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bits"));
                            }
                            width__ = map_.next_value::<::std::option::Option<::pbjson::private::NumberDeserialize<_>>>()?.map(|x| field_width::Width::Bits(x.0));
                        }
                        GeneratedField::ByteLen => {
                            if width__.is_some() {
                                return Err(serde::de::Error::duplicate_field("byteLen"));
                            }
                            width__ = map_.next_value::<::std::option::Option<_>>()?.map(field_width::Width::ByteLen)
;
                        }
                    }
                }
                Ok(FieldWidth {
                    width: width__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.FieldWidth", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for HeaderType {
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
        if !self.fields.is_empty() {
            len += 1;
        }
        if !self.annotations.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.HeaderType", len)?;
        if !self.name.is_empty() {
            struct_ser.serialize_field("name", &self.name)?;
        }
        if !self.fields.is_empty() {
            struct_ser.serialize_field("fields", &self.fields)?;
        }
        if !self.annotations.is_empty() {
            struct_ser.serialize_field("annotations", &self.annotations)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for HeaderType {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "name",
            "fields",
            "annotations",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Name,
            Fields,
            Annotations,
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
                            "fields" => Ok(GeneratedField::Fields),
                            "annotations" => Ok(GeneratedField::Annotations),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = HeaderType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.HeaderType")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<HeaderType, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut name__ = None;
                let mut fields__ = None;
                let mut annotations__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Name => {
                            if name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Fields => {
                            if fields__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fields"));
                            }
                            fields__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Annotations => {
                            if annotations__.is_some() {
                                return Err(serde::de::Error::duplicate_field("annotations"));
                            }
                            annotations__ = Some(
                                map_.next_value::<std::collections::BTreeMap<_, _>>()?
                            );
                        }
                    }
                }
                Ok(HeaderType {
                    name: name__.unwrap_or_default(),
                    fields: fields__.unwrap_or_default(),
                    annotations: annotations__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.HeaderType", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Ir {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.ir_version.is_empty() {
            len += 1;
        }
        if self.parser.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Ir", len)?;
        if !self.ir_version.is_empty() {
            struct_ser.serialize_field("irVersion", &self.ir_version)?;
        }
        if let Some(v) = self.parser.as_ref() {
            struct_ser.serialize_field("parser", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Ir {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "ir_version",
            "irVersion",
            "parser",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            IrVersion,
            Parser,
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
                            "irVersion" | "ir_version" => Ok(GeneratedField::IrVersion),
                            "parser" => Ok(GeneratedField::Parser),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Ir;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Ir")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Ir, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut ir_version__ = None;
                let mut parser__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::IrVersion => {
                            if ir_version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("irVersion"));
                            }
                            ir_version__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Parser => {
                            if parser__.is_some() {
                                return Err(serde::de::Error::duplicate_field("parser"));
                            }
                            parser__ = map_.next_value()?;
                        }
                    }
                }
                Ok(Ir {
                    ir_version: ir_version__.unwrap_or_default(),
                    parser: parser__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Ir", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for KeysetEntry {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.kind.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.KeysetEntry", len)?;
        if let Some(v) = self.kind.as_ref() {
            match v {
                keyset_entry::Kind::Value(v) => {
                    #[allow(clippy::needless_borrow)]
                    #[allow(clippy::needless_borrows_for_generic_args)]
                    struct_ser.serialize_field("value", ToString::to_string(&v).as_str())?;
                }
                keyset_entry::Kind::Masked(v) => {
                    struct_ser.serialize_field("masked", v)?;
                }
                keyset_entry::Kind::Range(v) => {
                    struct_ser.serialize_field("range", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for KeysetEntry {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "value",
            "masked",
            "range",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Value,
            Masked,
            Range,
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
                            "value" => Ok(GeneratedField::Value),
                            "masked" => Ok(GeneratedField::Masked),
                            "range" => Ok(GeneratedField::Range),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = KeysetEntry;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.KeysetEntry")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<KeysetEntry, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut kind__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Value => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<::pbjson::private::NumberDeserialize<_>>>()?.map(|x| keyset_entry::Kind::Value(x.0));
                        }
                        GeneratedField::Masked => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("masked"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(keyset_entry::Kind::Masked)
;
                        }
                        GeneratedField::Range => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("range"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(keyset_entry::Kind::Range)
;
                        }
                    }
                }
                Ok(KeysetEntry {
                    kind: kind__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.KeysetEntry", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Masked {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.value != 0 {
            len += 1;
        }
        if self.mask != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Masked", len)?;
        if self.value != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("value", ToString::to_string(&self.value).as_str())?;
        }
        if self.mask != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("mask", ToString::to_string(&self.mask).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Masked {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "value",
            "mask",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Value,
            Mask,
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
                            "value" => Ok(GeneratedField::Value),
                            "mask" => Ok(GeneratedField::Mask),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Masked;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Masked")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Masked, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut value__ = None;
                let mut mask__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Value => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            value__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Mask => {
                            if mask__.is_some() {
                                return Err(serde::de::Error::duplicate_field("mask"));
                            }
                            mask__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(Masked {
                    value: value__.unwrap_or_default(),
                    mask: mask__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Masked", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for MetadataField {
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
        if self.bits != 0 {
            len += 1;
        }
        if self.init != 0 {
            len += 1;
        }
        if self.display.is_some() {
            len += 1;
        }
        if !self.annotations.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.MetadataField", len)?;
        if !self.name.is_empty() {
            struct_ser.serialize_field("name", &self.name)?;
        }
        if self.bits != 0 {
            struct_ser.serialize_field("bits", &self.bits)?;
        }
        if self.init != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("init", ToString::to_string(&self.init).as_str())?;
        }
        if let Some(v) = self.display.as_ref() {
            struct_ser.serialize_field("display", v)?;
        }
        if !self.annotations.is_empty() {
            struct_ser.serialize_field("annotations", &self.annotations)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for MetadataField {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "name",
            "bits",
            "init",
            "display",
            "annotations",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Name,
            Bits,
            Init,
            Display,
            Annotations,
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
                            "bits" => Ok(GeneratedField::Bits),
                            "init" => Ok(GeneratedField::Init),
                            "display" => Ok(GeneratedField::Display),
                            "annotations" => Ok(GeneratedField::Annotations),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MetadataField;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.MetadataField")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<MetadataField, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut name__ = None;
                let mut bits__ = None;
                let mut init__ = None;
                let mut display__ = None;
                let mut annotations__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Name => {
                            if name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Bits => {
                            if bits__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bits"));
                            }
                            bits__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Init => {
                            if init__.is_some() {
                                return Err(serde::de::Error::duplicate_field("init"));
                            }
                            init__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Display => {
                            if display__.is_some() {
                                return Err(serde::de::Error::duplicate_field("display"));
                            }
                            display__ = map_.next_value()?;
                        }
                        GeneratedField::Annotations => {
                            if annotations__.is_some() {
                                return Err(serde::de::Error::duplicate_field("annotations"));
                            }
                            annotations__ = Some(
                                map_.next_value::<std::collections::BTreeMap<_, _>>()?
                            );
                        }
                    }
                }
                Ok(MetadataField {
                    name: name__.unwrap_or_default(),
                    bits: bits__.unwrap_or_default(),
                    init: init__.unwrap_or_default(),
                    display: display__,
                    annotations: annotations__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.MetadataField", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for MetadataRef {
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
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.MetadataRef", len)?;
        if !self.name.is_empty() {
            struct_ser.serialize_field("name", &self.name)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for MetadataRef {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "name",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Name,
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
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MetadataRef;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.MetadataRef")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<MetadataRef, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut name__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Name => {
                            if name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(MetadataRef {
                    name: name__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.MetadataRef", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Parser {
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
        if !self.header_types.is_empty() {
            len += 1;
        }
        if !self.states.is_empty() {
            len += 1;
        }
        if !self.start_state.is_empty() {
            len += 1;
        }
        if self.max_depth != 0 {
            len += 1;
        }
        if !self.metadata.is_empty() {
            len += 1;
        }
        if !self.annotations.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Parser", len)?;
        if !self.name.is_empty() {
            struct_ser.serialize_field("name", &self.name)?;
        }
        if !self.header_types.is_empty() {
            struct_ser.serialize_field("headerTypes", &self.header_types)?;
        }
        if !self.states.is_empty() {
            struct_ser.serialize_field("states", &self.states)?;
        }
        if !self.start_state.is_empty() {
            struct_ser.serialize_field("startState", &self.start_state)?;
        }
        if self.max_depth != 0 {
            struct_ser.serialize_field("maxDepth", &self.max_depth)?;
        }
        if !self.metadata.is_empty() {
            struct_ser.serialize_field("metadata", &self.metadata)?;
        }
        if !self.annotations.is_empty() {
            struct_ser.serialize_field("annotations", &self.annotations)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Parser {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "name",
            "header_types",
            "headerTypes",
            "states",
            "start_state",
            "startState",
            "max_depth",
            "maxDepth",
            "metadata",
            "annotations",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Name,
            HeaderTypes,
            States,
            StartState,
            MaxDepth,
            Metadata,
            Annotations,
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
                            "headerTypes" | "header_types" => Ok(GeneratedField::HeaderTypes),
                            "states" => Ok(GeneratedField::States),
                            "startState" | "start_state" => Ok(GeneratedField::StartState),
                            "maxDepth" | "max_depth" => Ok(GeneratedField::MaxDepth),
                            "metadata" => Ok(GeneratedField::Metadata),
                            "annotations" => Ok(GeneratedField::Annotations),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Parser;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Parser")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Parser, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut name__ = None;
                let mut header_types__ = None;
                let mut states__ = None;
                let mut start_state__ = None;
                let mut max_depth__ = None;
                let mut metadata__ = None;
                let mut annotations__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Name => {
                            if name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::HeaderTypes => {
                            if header_types__.is_some() {
                                return Err(serde::de::Error::duplicate_field("headerTypes"));
                            }
                            header_types__ = Some(map_.next_value()?);
                        }
                        GeneratedField::States => {
                            if states__.is_some() {
                                return Err(serde::de::Error::duplicate_field("states"));
                            }
                            states__ = Some(map_.next_value()?);
                        }
                        GeneratedField::StartState => {
                            if start_state__.is_some() {
                                return Err(serde::de::Error::duplicate_field("startState"));
                            }
                            start_state__ = Some(map_.next_value()?);
                        }
                        GeneratedField::MaxDepth => {
                            if max_depth__.is_some() {
                                return Err(serde::de::Error::duplicate_field("maxDepth"));
                            }
                            max_depth__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Metadata => {
                            if metadata__.is_some() {
                                return Err(serde::de::Error::duplicate_field("metadata"));
                            }
                            metadata__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Annotations => {
                            if annotations__.is_some() {
                                return Err(serde::de::Error::duplicate_field("annotations"));
                            }
                            annotations__ = Some(
                                map_.next_value::<std::collections::BTreeMap<_, _>>()?
                            );
                        }
                    }
                }
                Ok(Parser {
                    name: name__.unwrap_or_default(),
                    header_types: header_types__.unwrap_or_default(),
                    states: states__.unwrap_or_default(),
                    start_state: start_state__.unwrap_or_default(),
                    max_depth: max_depth__.unwrap_or_default(),
                    metadata: metadata__.unwrap_or_default(),
                    annotations: annotations__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Parser", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Pop {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let len = 0;
        let struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Pop", len)?;
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Pop {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
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
                            Err(serde::de::Error::unknown_field(value, FIELDS))
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Pop;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Pop")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Pop, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                while map_.next_key::<GeneratedField>()?.is_some() {
                    let _ = map_.next_value::<serde::de::IgnoredAny>()?;
                }
                Ok(Pop {
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Pop", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Range {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.lo != 0 {
            len += 1;
        }
        if self.hi != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Range", len)?;
        if self.lo != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("lo", ToString::to_string(&self.lo).as_str())?;
        }
        if self.hi != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("hi", ToString::to_string(&self.hi).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Range {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "lo",
            "hi",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Lo,
            Hi,
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
                            "lo" => Ok(GeneratedField::Lo),
                            "hi" => Ok(GeneratedField::Hi),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Range;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Range")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Range, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut lo__ = None;
                let mut hi__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Lo => {
                            if lo__.is_some() {
                                return Err(serde::de::Error::duplicate_field("lo"));
                            }
                            lo__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Hi => {
                            if hi__.is_some() {
                                return Err(serde::de::Error::duplicate_field("hi"));
                            }
                            hi__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                    }
                }
                Ok(Range {
                    lo: lo__.unwrap_or_default(),
                    hi: hi__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Range", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for RegionOp {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.kind.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.RegionOp", len)?;
        if let Some(v) = self.kind.as_ref() {
            match v {
                region_op::Kind::Push(v) => {
                    struct_ser.serialize_field("push", v)?;
                }
                region_op::Kind::Pop(v) => {
                    struct_ser.serialize_field("pop", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for RegionOp {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "push",
            "pop",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Push,
            Pop,
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
                            "push" => Ok(GeneratedField::Push),
                            "pop" => Ok(GeneratedField::Pop),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = RegionOp;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.RegionOp")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<RegionOp, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut kind__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Push => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("push"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(region_op::Kind::Push)
;
                        }
                        GeneratedField::Pop => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("pop"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(region_op::Kind::Pop)
;
                        }
                    }
                }
                Ok(RegionOp {
                    kind: kind__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.RegionOp", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Reject {
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
        if !self.annotations.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Reject", len)?;
        if !self.reason.is_empty() {
            struct_ser.serialize_field("reason", &self.reason)?;
        }
        if !self.annotations.is_empty() {
            struct_ser.serialize_field("annotations", &self.annotations)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Reject {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "reason",
            "annotations",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Reason,
            Annotations,
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
                            "annotations" => Ok(GeneratedField::Annotations),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Reject;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Reject")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Reject, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut reason__ = None;
                let mut annotations__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Reason => {
                            if reason__.is_some() {
                                return Err(serde::de::Error::duplicate_field("reason"));
                            }
                            reason__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Annotations => {
                            if annotations__.is_some() {
                                return Err(serde::de::Error::duplicate_field("annotations"));
                            }
                            annotations__ = Some(
                                map_.next_value::<std::collections::BTreeMap<_, _>>()?
                            );
                        }
                    }
                }
                Ok(Reject {
                    reason: reason__.unwrap_or_default(),
                    annotations: annotations__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Reject", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Remaining {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let len = 0;
        let struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Remaining", len)?;
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Remaining {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
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
                            Err(serde::de::Error::unknown_field(value, FIELDS))
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Remaining;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Remaining")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Remaining, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                while map_.next_key::<GeneratedField>()?.is_some() {
                    let _ = map_.next_value::<serde::de::IgnoredAny>()?;
                }
                Ok(Remaining {
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Remaining", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Select {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.keys.is_empty() {
            len += 1;
        }
        if !self.arms.is_empty() {
            len += 1;
        }
        if self.default_target.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Select", len)?;
        if !self.keys.is_empty() {
            struct_ser.serialize_field("keys", &self.keys)?;
        }
        if !self.arms.is_empty() {
            struct_ser.serialize_field("arms", &self.arms)?;
        }
        if let Some(v) = self.default_target.as_ref() {
            struct_ser.serialize_field("defaultTarget", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Select {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "keys",
            "arms",
            "default_target",
            "defaultTarget",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Keys,
            Arms,
            DefaultTarget,
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
                            "keys" => Ok(GeneratedField::Keys),
                            "arms" => Ok(GeneratedField::Arms),
                            "defaultTarget" | "default_target" => Ok(GeneratedField::DefaultTarget),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Select;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Select")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Select, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut keys__ = None;
                let mut arms__ = None;
                let mut default_target__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Keys => {
                            if keys__.is_some() {
                                return Err(serde::de::Error::duplicate_field("keys"));
                            }
                            keys__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Arms => {
                            if arms__.is_some() {
                                return Err(serde::de::Error::duplicate_field("arms"));
                            }
                            arms__ = Some(map_.next_value()?);
                        }
                        GeneratedField::DefaultTarget => {
                            if default_target__.is_some() {
                                return Err(serde::de::Error::duplicate_field("defaultTarget"));
                            }
                            default_target__ = map_.next_value()?;
                        }
                    }
                }
                Ok(Select {
                    keys: keys__.unwrap_or_default(),
                    arms: arms__.unwrap_or_default(),
                    default_target: default_target__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Select", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for SelectArm {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.entries.is_empty() {
            len += 1;
        }
        if self.next.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.SelectArm", len)?;
        if !self.entries.is_empty() {
            struct_ser.serialize_field("entries", &self.entries)?;
        }
        if let Some(v) = self.next.as_ref() {
            struct_ser.serialize_field("next", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SelectArm {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "entries",
            "next",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Entries,
            Next,
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
                            "entries" => Ok(GeneratedField::Entries),
                            "next" => Ok(GeneratedField::Next),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SelectArm;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.SelectArm")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<SelectArm, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut entries__ = None;
                let mut next__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Entries => {
                            if entries__.is_some() {
                                return Err(serde::de::Error::duplicate_field("entries"));
                            }
                            entries__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Next => {
                            if next__.is_some() {
                                return Err(serde::de::Error::duplicate_field("next"));
                            }
                            next__ = map_.next_value()?;
                        }
                    }
                }
                Ok(SelectArm {
                    entries: entries__.unwrap_or_default(),
                    next: next__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.SelectArm", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for State {
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
        if !self.extracts.is_empty() {
            len += 1;
        }
        if self.transition.is_some() {
            len += 1;
        }
        if !self.assigns.is_empty() {
            len += 1;
        }
        if !self.region_ops.is_empty() {
            len += 1;
        }
        if !self.annotations.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.State", len)?;
        if !self.name.is_empty() {
            struct_ser.serialize_field("name", &self.name)?;
        }
        if !self.extracts.is_empty() {
            struct_ser.serialize_field("extracts", &self.extracts)?;
        }
        if let Some(v) = self.transition.as_ref() {
            struct_ser.serialize_field("transition", v)?;
        }
        if !self.assigns.is_empty() {
            struct_ser.serialize_field("assigns", &self.assigns)?;
        }
        if !self.region_ops.is_empty() {
            struct_ser.serialize_field("regionOps", &self.region_ops)?;
        }
        if !self.annotations.is_empty() {
            struct_ser.serialize_field("annotations", &self.annotations)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for State {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "name",
            "extracts",
            "transition",
            "assigns",
            "region_ops",
            "regionOps",
            "annotations",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Name,
            Extracts,
            Transition,
            Assigns,
            RegionOps,
            Annotations,
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
                            "extracts" => Ok(GeneratedField::Extracts),
                            "transition" => Ok(GeneratedField::Transition),
                            "assigns" => Ok(GeneratedField::Assigns),
                            "regionOps" | "region_ops" => Ok(GeneratedField::RegionOps),
                            "annotations" => Ok(GeneratedField::Annotations),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = State;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.State")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<State, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut name__ = None;
                let mut extracts__ = None;
                let mut transition__ = None;
                let mut assigns__ = None;
                let mut region_ops__ = None;
                let mut annotations__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Name => {
                            if name__.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Extracts => {
                            if extracts__.is_some() {
                                return Err(serde::de::Error::duplicate_field("extracts"));
                            }
                            extracts__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Transition => {
                            if transition__.is_some() {
                                return Err(serde::de::Error::duplicate_field("transition"));
                            }
                            transition__ = map_.next_value()?;
                        }
                        GeneratedField::Assigns => {
                            if assigns__.is_some() {
                                return Err(serde::de::Error::duplicate_field("assigns"));
                            }
                            assigns__ = Some(map_.next_value()?);
                        }
                        GeneratedField::RegionOps => {
                            if region_ops__.is_some() {
                                return Err(serde::de::Error::duplicate_field("regionOps"));
                            }
                            region_ops__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Annotations => {
                            if annotations__.is_some() {
                                return Err(serde::de::Error::duplicate_field("annotations"));
                            }
                            annotations__ = Some(
                                map_.next_value::<std::collections::BTreeMap<_, _>>()?
                            );
                        }
                    }
                }
                Ok(State {
                    name: name__.unwrap_or_default(),
                    extracts: extracts__.unwrap_or_default(),
                    transition: transition__,
                    assigns: assigns__.unwrap_or_default(),
                    region_ops: region_ops__.unwrap_or_default(),
                    annotations: annotations__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.State", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Target {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.kind.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Target", len)?;
        if let Some(v) = self.kind.as_ref() {
            match v {
                target::Kind::State(v) => {
                    struct_ser.serialize_field("state", v)?;
                }
                target::Kind::Accept(v) => {
                    struct_ser.serialize_field("accept", v)?;
                }
                target::Kind::Reject(v) => {
                    struct_ser.serialize_field("reject", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Target {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "state",
            "accept",
            "reject",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            State,
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
                            "state" => Ok(GeneratedField::State),
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
            type Value = Target;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Target")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Target, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut kind__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::State => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("state"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(target::Kind::State);
                        }
                        GeneratedField::Accept => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("accept"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(target::Kind::Accept)
;
                        }
                        GeneratedField::Reject => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("reject"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(target::Kind::Reject)
;
                        }
                    }
                }
                Ok(Target {
                    kind: kind__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Target", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for Transition {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.kind.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.Transition", len)?;
        if let Some(v) = self.kind.as_ref() {
            match v {
                transition::Kind::Direct(v) => {
                    struct_ser.serialize_field("direct", v)?;
                }
                transition::Kind::Select(v) => {
                    struct_ser.serialize_field("select", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Transition {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "direct",
            "select",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Direct,
            Select,
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
                            "direct" => Ok(GeneratedField::Direct),
                            "select" => Ok(GeneratedField::Select),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Transition;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.Transition")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Transition, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut kind__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Direct => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("direct"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(transition::Kind::Direct)
;
                        }
                        GeneratedField::Select => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("select"));
                            }
                            kind__ = map_.next_value::<::std::option::Option<_>>()?.map(transition::Kind::Select)
;
                        }
                    }
                }
                Ok(Transition {
                    kind: kind__,
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.Transition", FIELDS, GeneratedVisitor)
    }
}
impl serde::Serialize for ValueLabel {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.value != 0 {
            len += 1;
        }
        if !self.label.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("pakeles.ir.v1alpha1.ValueLabel", len)?;
        if self.value != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("value", ToString::to_string(&self.value).as_str())?;
        }
        if !self.label.is_empty() {
            struct_ser.serialize_field("label", &self.label)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for ValueLabel {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "value",
            "label",
        ];

        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Value,
            Label,
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
                            "value" => Ok(GeneratedField::Value),
                            "label" => Ok(GeneratedField::Label),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = ValueLabel;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct pakeles.ir.v1alpha1.ValueLabel")
            }

            fn visit_map<V>(self, mut map_: V) -> std::result::Result<ValueLabel, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
            {
                let mut value__ = None;
                let mut label__ = None;
                while let Some(k) = map_.next_key()? {
                    match k {
                        GeneratedField::Value => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            value__ = 
                                Some(map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0)
                            ;
                        }
                        GeneratedField::Label => {
                            if label__.is_some() {
                                return Err(serde::de::Error::duplicate_field("label"));
                            }
                            label__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(ValueLabel {
                    value: value__.unwrap_or_default(),
                    label: label__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("pakeles.ir.v1alpha1.ValueLabel", FIELDS, GeneratedVisitor)
    }
}
