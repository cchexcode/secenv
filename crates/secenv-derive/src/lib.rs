use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Data, Fields, Variant};

/// Derive macro that automatically implements HoconEnum for enums
/// 
/// Usage:
/// ```rust
/// #[derive(HoconEnum)]
/// enum MyEnum {
///     SimpleVariant(String),
///     StructVariant { field1: String, field2: i32 },
/// }
/// ```
/// 
/// This allows HOCON like:
/// ```hocon
/// my_field.simple_variant = "value"
/// my_field.struct_variant.field1 = "value"
/// my_field.struct_variant.field2 = 42
/// ```
#[proc_macro_derive(HoconEnum)]
pub fn derive_hocon_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    
    match generate_hocon_enum_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn generate_hocon_enum_impl(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let enum_name = &input.ident;
    
    let data = match &input.data {
        Data::Enum(data) => data,
        _ => return Err(syn::Error::new_spanned(input, "HoconEnum can only be derived for enums")),
    };
    
    let mut match_arms = Vec::new();
    let mut variant_names = Vec::new();
    
    for variant in &data.variants {
        let variant_name = &variant.ident;
        let variant_name_str = variant_name.to_string().to_lowercase();
        variant_names.push(variant_name_str.clone());
        
        let match_arm = generate_variant_match_arm(enum_name, variant)?;
        match_arms.push(quote! {
            #variant_name_str => #match_arm
        });
    }
    
    let variant_names_array = variant_names.iter().collect::<Vec<_>>();
    
    Ok(quote! {
        impl crate::manifest::HoconEnum for #enum_name {
            fn deserialize_from_map<'de, M>(variant_name: &str, mut map: M) -> Result<Self, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                use serde::de::Error;
                match variant_name.to_lowercase().as_str() {
                    #(#match_arms,)*
                    _ => Err(M::Error::unknown_variant(variant_name, &[#(#variant_names_array),*]))
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for #enum_name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                crate::manifest::deserialize_hocon_enum(deserializer)
            }
        }
    })
}

fn generate_variant_match_arm(enum_name: &syn::Ident, variant: &Variant) -> syn::Result<proc_macro2::TokenStream> {
    let variant_name = &variant.ident;
    
    match &variant.fields {
        Fields::Unit => {
            // Unit variant: Variant
            Ok(quote! {
                {
                    // For unit variants, we expect no additional data
                    let _: () = map.next_value()?;
                    Ok(#enum_name::#variant_name)
                }
            })
        }
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            // Single field variant: Variant(Type)
            let field_type = &fields.unnamed.first().unwrap().ty;
            Ok(quote! {
                {
                    let value: #field_type = map.next_value()?;
                    Ok(#enum_name::#variant_name(value))
                }
            })
        }
        Fields::Unnamed(_) => {
            // Multiple unnamed fields: Variant(Type1, Type2, ...)
            Err(syn::Error::new_spanned(variant, "Multiple unnamed fields are not supported"))
        }
        Fields::Named(fields) => {
            // Struct variant: Variant { field1: Type1, field2: Type2 }
            let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();
            let field_types: Vec<_> = fields.named.iter().map(|f| &f.ty).collect();
            
            Ok(quote! {
                {
                    #[derive(serde::Deserialize)]
                    struct Fields {
                        #(#field_names: #field_types),*
                    }
                    let fields: Fields = map.next_value()?;
                    Ok(#enum_name::#variant_name {
                        #(#field_names: fields.#field_names),*
                    })
                }
            })
        }
    }
}
