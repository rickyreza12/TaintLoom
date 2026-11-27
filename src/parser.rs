use crate::Event;
use tree_sitter::{Node, Parser};

pub fn parse(source: &str, python: bool) -> Result<(Vec<Event>, Vec<String>), String> {
    let mut parser = Parser::new();
    let language = if python {
        tree_sitter_python::LANGUAGE.into()
    } else {
        tree_sitter_c::LANGUAGE.into()
    };
    parser.set_language(&language).map_err(|e| e.to_string())?;
    let tree = parser
        .parse(source, None)
        .ok_or("parser returned no tree")?;
    let mut lower = Lower {
        source,
        events: Vec::new(),
        warnings: Vec::new(),
        exhausted: false,
    };
    if tree.root_node().has_error() {
        lower
            .warnings
            .push("syntax errors: results may be incomplete".into());
    }
    lower.walk(tree.root_node(), 0);
    Ok((lower.events, lower.warnings))
}
struct Lower<'a> {
    source: &'a str,
    events: Vec<Event>,
    warnings: Vec<String>,
    exhausted: bool,
}
impl Lower<'_> {
    fn text(&self, n: Node<'_>) -> String {
        n.utf8_text(self.source.as_bytes()).unwrap_or("").to_owned()
    }
    fn field(&self, n: Node<'_>, name: &str) -> String {
        n.child_by_field_name(name)
            .map(|c| self.text(c))
            .unwrap_or_default()
    }
    fn emit(&mut self, n: Node<'_>, kind: u32, target: String, expression: String, callee: String) {
        if self.events.len() >= 20000 {
            self.limit();
            return;
        }
        self.events.push(Event {
            kind,
            line: (n.start_position().row + 1) as u32,
            target,
            expression,
            callee,
        });
    }
    fn limit(&mut self) {
        if !self.exhausted {
            self.warnings.push("syntax traversal limit reached".into());
            self.exhausted = true;
        }
    }
    fn warn(&mut self, n: Node<'_>) {
        if self.warnings.len() < 100 {
            self.warnings.push(format!(
                "line {}: unsupported construct {}",
                n.start_position().row + 1,
                n.kind()
            ));
        }
    }
    fn call(&self, n: Node<'_>) -> String {
        if matches!(n.kind(), "call" | "call_expression") {
            self.field(n, "function")
        } else {
            String::new()
        }
    }
    fn children(&mut self, n: Node<'_>, depth: usize) {
        let mut cursor = n.walk();
        for c in n.named_children(&mut cursor) {
            self.walk(c, depth + 1);
        }
    }
    fn declarator_name(&self, mut n: Node<'_>) -> Option<String> {
        for _ in 0..32 {
            if n.kind() == "identifier" {
                return Some(self.text(n));
            }
            n = n.child_by_field_name("declarator")?;
        }
        None
    }
    fn params(&self, n: Node<'_>) -> String {
        let mut cur = n.walk();
        n.named_children(&mut cur)
            .filter_map(|p| {
                if p.kind() == "identifier" {
                    Some(self.text(p))
                } else {
                    p.child_by_field_name("name")
                        .or_else(|| p.child_by_field_name("declarator"))
                        .and_then(|x| self.declarator_name(x))
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
    fn walk(&mut self, n: Node<'_>, depth: usize) {
        if self.exhausted {
            return;
        }
        if depth > 256 {
            self.limit();
            return;
        }
        match n.kind() {
            "function_definition" => {
                let decl = n.child_by_field_name("declarator");
                let name = if let Some(d) = decl {
                    self.declarator_name(d).unwrap_or_default()
                } else {
                    self.field(n, "name")
                };
                let params = decl
                    .and_then(|d| d.child_by_field_name("parameters"))
                    .or_else(|| n.child_by_field_name("parameters"))
                    .map(|p| self.params(p))
                    .unwrap_or_default();
                self.emit(n, 5, name.clone(), params, String::new());
                if let Some(body) = n.child_by_field_name("body") {
                    self.walk(body, depth + 1);
                }
                self.emit(n, 6, name, String::new(), String::new());
            }
            "assignment" | "assignment_expression" | "init_declarator" => {
                let left = n
                    .child_by_field_name("left")
                    .or_else(|| n.child_by_field_name("declarator"));
                let right = n
                    .child_by_field_name("right")
                    .or_else(|| n.child_by_field_name("value"));
                if let (Some(l), Some(r)) = (left, right) {
                    let name = if n.kind() == "init_declarator" {
                        self.declarator_name(l)
                    } else if l.kind() == "identifier" {
                        Some(self.text(l))
                    } else {
                        None
                    };
                    if name.is_none() {
                        self.warn(l);
                    }
                    let target = name.unwrap_or_else(|| self.text(l));
                    self.emit(n, 1, target, self.text(r), self.call(r));
                } else {
                    self.warn(n);
                }
            }
            "call" | "call_expression" => {
                self.emit(n, 2, String::new(), self.text(n), self.call(n))
            }
            "if_statement" => {
                let cond = self.field(n, "condition");
                self.emit(n, 3, String::new(), cond, String::new());
                if let Some(body) = n.child_by_field_name("consequence") {
                    self.walk(body, depth + 1);
                }
                self.emit(n, 4, String::new(), String::new(), String::new());
                if let Some(alt) = n.child_by_field_name("alternative") {
                    self.warn(alt);
                    self.walk(alt, depth + 1);
                }
            }
            "return_statement" => {
                let expression = n.named_child(0).map(|c| self.text(c)).unwrap_or_default();
                self.emit(n, 7, String::new(), expression, String::new());
            }
            "for_statement"
            | "while_statement"
            | "try_statement"
            | "switch_statement"
            | "goto_statement"
            | "with_statement"
            | "lambda"
            | "list_comprehension"
            | "augmented_assignment"
            | "preproc_if"
            | "preproc_ifdef" => {
                self.warn(n);
                self.children(n, depth);
            }
            _ => self.children(n, depth),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_events() {
        let (e, w) = parse(
            "def f(x):\n    y = request(x)\n    if authorized(x):\n        send(y)\n    return y\n",
            true,
        )
        .unwrap();
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(
            e.iter().map(|e| e.kind).collect::<Vec<_>>(),
            vec![5, 1, 3, 2, 4, 7, 6]
        );
        assert_eq!(e[1].callee, "request");
    }
    #[test]
    fn c_events() {
        let (e, w) = parse("void f(int x) { int y = read_secret(); send(y); }", false).unwrap();
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(e[1].callee, "read_secret");
        assert_eq!(e[0].expression, "x");
    }
    #[test]
    fn c_pointer_declarations() {
        let (events, warnings) = parse(
            "void f(const char *name) { char *secret = getenv(\"KEY\"); printf(\"%s\", secret); }",
            false,
        )
        .unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(events[0].expression, "name");
        assert_eq!(events[1].target, "secret");
        assert_eq!(events[1].callee, "getenv");
    }
    #[test]
    fn malformed() {
        assert!(!parse("def f(:", true).unwrap().1.is_empty());
    }
}
