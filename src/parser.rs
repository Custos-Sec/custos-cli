//! Lightweight struct parser using syn
//!
//! This module provides minimal AST parsing focused only on struct extraction.
//! It does NOT build a full program IR - just enough to understand struct definitions.

use std::collections::HashMap;

/// Information about a parsed struct
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StructInfo {
    /// Struct name
    pub name: String,
    /// Line number in source
    pub line: usize,
    /// Fields in the struct
    pub fields: Vec<FieldInfo>,
    /// Whether this has #[account] attribute (Anchor state)
    pub is_account: bool,
    /// Whether this derives Accounts (Anchor context)
    pub is_accounts_context: bool,
    /// Raw attributes for additional analysis
    pub attributes: Vec<String>,
}

/// Information about a struct field
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FieldInfo {
    /// Field name
    pub name: String,
    /// Field type as string
    pub ty: String,
    /// Line number
    pub line: usize,
    /// Whether field is public
    pub is_pub: bool,
    /// Anchor constraints if present (e.g., "mut", "seeds = [...]")
    pub constraints: Vec<String>,
    /// Whether this is a mutable account
    pub is_mut: bool,
    /// Whether this is a signer
    pub is_signer: bool,
    /// Seeds if this is a PDA
    pub seeds: Option<String>,
}

/// Parse all structs from Rust source code
pub fn parse_structs(content: &str) -> Vec<StructInfo> {
    let Ok(file) = syn::parse_file(content) else {
        return Vec::new();
    };

    let mut structs = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for item in file.items {
        if let syn::Item::Struct(s) = item {
            let struct_info = parse_struct_item(&s, &lines, content);
            structs.push(struct_info);
        }
    }

    structs
}

/// Parse a single struct item
fn parse_struct_item(s: &syn::ItemStruct, _lines: &[&str], content: &str) -> StructInfo {
    let name = s.ident.to_string();
    let line = get_line_number(s.ident.span(), content);

    // Check attributes
    let mut is_account = false;
    let mut is_accounts_context = false;
    let mut attributes = Vec::new();

    for attr in &s.attrs {
        let attr_str = attr_to_string(attr);
        attributes.push(attr_str.clone());

        // Check for #[account] or #[account(...)]
        if attr_str.contains("account") {
            is_account = true;
        }

        // Check for #[derive(...Accounts...)]
        if attr_str.contains("Accounts") && attr_str.contains("derive") {
            is_accounts_context = true;
        }
    }

    // Parse fields
    let fields = match &s.fields {
        syn::Fields::Named(named) => {
            named.named.iter().map(|f| parse_field(f, content)).collect()
        }
        _ => Vec::new(),
    };

    StructInfo {
        name,
        line,
        fields,
        is_account,
        is_accounts_context,
        attributes,
    }
}

/// Parse a single field
fn parse_field(f: &syn::Field, content: &str) -> FieldInfo {
    let name = f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
    let ty = type_to_string(&f.ty);
    let line = f.ident.as_ref()
        .map(|i| get_line_number(i.span(), content))
        .unwrap_or(0);

    let is_pub = matches!(f.vis, syn::Visibility::Public(_));

    // Parse Anchor constraints from attributes
    let mut constraints = Vec::new();
    let mut is_mut = false;
    let mut is_signer = false;
    let mut seeds = None;

    for attr in &f.attrs {
        let attr_str = attr_to_string(attr);

        // Look for #[account(...)]
        if attr_str.contains("account") {
            // Extract the constraint content
            if let Some(start) = attr_str.find('(') {
                if let Some(end) = attr_str.rfind(')') {
                    let constraint_str = &attr_str[start + 1..end];
                    constraints.push(constraint_str.to_string());

                    // Check for specific constraints
                    if constraint_str.contains("mut") {
                        is_mut = true;
                    }
                    if constraint_str.contains("signer") || attr_str.contains("Signer") {
                        is_signer = true;
                    }
                    if constraint_str.contains("seeds") {
                        // Extract seeds value
                        if let Some(seeds_start) = constraint_str.find("seeds") {
                            let rest = &constraint_str[seeds_start..];
                            if let Some(bracket_start) = rest.find('[') {
                                if let Some(bracket_end) = rest.find(']') {
                                    seeds = Some(rest[bracket_start..=bracket_end].to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check if the type itself indicates signer
    if ty.contains("Signer") {
        is_signer = true;
    }

    FieldInfo {
        name,
        ty,
        line,
        is_pub,
        constraints,
        is_mut,
        is_signer,
        seeds,
    }
}

/// Convert a syn::Type to a string representation
fn type_to_string(ty: &syn::Type) -> String {
    use syn::Type;

    match ty {
        Type::Path(tp) => {
            tp.path.segments.iter()
                .map(|seg| {
                    let name = seg.ident.to_string();
                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                        let inner: Vec<String> = args.args.iter()
                            .filter_map(|arg| {
                                if let syn::GenericArgument::Type(t) = arg {
                                    Some(type_to_string(t))
                                } else {
                                    None
                                }
                            })
                            .collect();
                        if inner.is_empty() {
                            name
                        } else {
                            format!("{}<{}>", name, inner.join(", "))
                        }
                    } else {
                        name
                    }
                })
                .collect::<Vec<_>>()
                .join("::")
        }
        Type::Reference(r) => {
            let inner = type_to_string(&r.elem);
            if r.mutability.is_some() {
                format!("&mut {}", inner)
            } else {
                format!("&{}", inner)
            }
        }
        Type::Array(a) => {
            format!("[{}; ...]", type_to_string(&a.elem))
        }
        Type::Slice(s) => {
            format!("[{}]", type_to_string(&s.elem))
        }
        _ => "unknown".to_string(),
    }
}

/// Get line number from a span
fn get_line_number(_span: proc_macro2::Span, _content: &str) -> usize {
    // proc_macro2 spans don't have reliable line info outside of proc macros
    // Line numbers are calculated separately from content matching
    1
}

/// Convert a syn::Attribute to a string representation
fn attr_to_string(attr: &syn::Attribute) -> String {
    // Get the path (e.g., "account", "derive")
    let path = attr.path().segments.iter()
        .map(|seg| seg.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");

    // Get the tokens inside if any
    match &attr.meta {
        syn::Meta::Path(_) => format!("#[{}]", path),
        syn::Meta::List(list) => {
            let tokens = list.tokens.to_string();
            format!("#[{}({})]", path, tokens)
        }
        syn::Meta::NameValue(_nv) => {
            // For name-value, just use the path and indicate there's a value
            format!("#[{} = ...]", path)
        }
    }
}

/// Build a map of struct name -> StructInfo for quick lookup
#[allow(dead_code)]
pub fn build_struct_map(structs: &[StructInfo]) -> HashMap<String, &StructInfo> {
    structs.iter().map(|s| (s.name.clone(), s)).collect()
}

/// Find which struct a line belongs to
#[allow(dead_code)]
pub fn find_containing_struct(structs: &[StructInfo], line: usize) -> Option<&StructInfo> {
    // Simple heuristic: find the struct whose definition line is closest before the target line
    structs.iter()
        .filter(|s| s.line <= line)
        .max_by_key(|s| s.line)
}

/// Check if a struct has an authority/signer field
#[allow(dead_code)]
pub fn has_authority_field(s: &StructInfo) -> bool {
    s.fields.iter().any(|f| {
        f.is_signer ||
        f.name.contains("authority") ||
        f.name.contains("owner") ||
        f.name.contains("admin") ||
        f.ty.contains("Signer")
    })
}

/// Check if a struct has mutable accounts without signers
#[allow(dead_code)]
pub fn has_unprotected_mut(s: &StructInfo) -> bool {
    if !s.is_accounts_context {
        return false;
    }

    let has_mut = s.fields.iter().any(|f| f.is_mut);
    let has_signer = has_authority_field(s);

    has_mut && !has_signer
}

/// Get all PDA fields with their seeds
pub fn get_pda_fields(s: &StructInfo) -> Vec<(&FieldInfo, &str)> {
    s.fields.iter()
        .filter_map(|f| f.seeds.as_ref().map(|seeds| (f, seeds.as_str())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_struct() {
        let code = r#"
            pub struct User {
                pub name: String,
                pub balance: u64,
            }
        "#;

        let structs = parse_structs(code);
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "User");
        assert_eq!(structs[0].fields.len(), 2);
        assert_eq!(structs[0].fields[0].name, "name");
        assert!(structs[0].fields[0].ty.contains("String"));
    }

    #[test]
    fn test_parse_anchor_account() {
        let code = r#"
            #[account]
            pub struct UserProfile {
                pub email: String,
                pub verified: bool,
            }
        "#;

        let structs = parse_structs(code);
        assert_eq!(structs.len(), 1);
        assert!(structs[0].is_account);
        assert!(!structs[0].is_accounts_context);
    }

    #[test]
    fn test_parse_accounts_context() {
        let code = r#"
            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut)]
                pub from: Account<'info, TokenAccount>,
                pub authority: Signer<'info>,
            }
        "#;

        let structs = parse_structs(code);
        assert_eq!(structs.len(), 1);
        assert!(structs[0].is_accounts_context);
        assert!(has_authority_field(&structs[0]));
    }

    #[test]
    fn test_detect_unprotected_mut() {
        let code = r#"
            #[derive(Accounts)]
            pub struct UnsafeUpdate<'info> {
                #[account(mut)]
                pub data: Account<'info, UserData>,
            }
        "#;

        let structs = parse_structs(code);
        assert!(has_unprotected_mut(&structs[0]));
    }
}
