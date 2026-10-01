use rustc_errors::Diag;
use rustc_hir::def_id::DefId;
use rustc_middle::mir;
use std::cmp::Ordering;
use std::collections::HashMap;

/// Define the cause of a diagnostic message
/// Used to provide user options to suppress some specific kinds of warnings
/// So that we can decrease the false-positive rate
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DiagnosticCause {
    Bitwise,    // Bit-wise overflow
    Arithmetic, // Arithmetic overflow
    Assembly,   // Inline assembly
    Comparison, // Comparison operations
    DivZero,    // Division by zero / remainder by zero
    Memory,     // Memory-safety issues
    Panic,      // Run into panic code
    Index,      // Out-of-bounds access
    Other,      // Other
}

/// Extract the cause of a diagnostic message from an assertion statement
impl<O> From<&mir::AssertKind<O>> for DiagnosticCause {
    fn from(assert_kind: &mir::AssertKind<O>) -> DiagnosticCause {
        use mir::BinOp::*;
        match assert_kind {
            mir::AssertKind::BoundsCheck { .. } => DiagnosticCause::Index,
            mir::AssertKind::Overflow(bin_op, ..) => match bin_op {
                Add | Sub | Mul | Div | Rem | AddUnchecked | SubUnchecked | MulUnchecked | AddWithOverflow | SubWithOverflow | MulWithOverflow => DiagnosticCause::Arithmetic,
                Shr | Shl | BitXor | BitAnd | BitOr | ShrUnchecked | ShlUnchecked => DiagnosticCause::Bitwise,
                Eq | Lt | Le | Ne | Ge | Gt | Cmp => DiagnosticCause::Comparison,
                Offset => DiagnosticCause::Index,
            },
            mir::AssertKind::OverflowNeg(..) => DiagnosticCause::Arithmetic,
            mir::AssertKind::DivisionByZero(..) | mir::AssertKind::RemainderByZero(..) => {
                DiagnosticCause::DivZero
            }
            mir::AssertKind::MisalignedPointerDereference { .. }
            | mir::AssertKind::NullPointerDereference => DiagnosticCause::Memory,
            _ => DiagnosticCause::Other,
        }
    }
}

impl<O> From<&Box<mir::AssertKind<O>>> for DiagnosticCause {
    fn from(assert_kind: &Box<mir::AssertKind<O>>) -> DiagnosticCause {
        assert_kind.as_ref().into()
    }
}

/// A diagnosis, which consists of the span, message and metadata
#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub span: rustc_span::Span,
    pub message: String,
    pub is_error: bool,
    pub is_memory_safety: bool,
    pub cause: DiagnosticCause,
}

impl Diagnostic {
    pub fn new(
        span: rustc_span::Span,
        message: String,
        is_error: bool,
        is_memory_safety: bool,
        cause: DiagnosticCause,
    ) -> Self {
        Self {
            span,
            message,
            is_error,
            is_memory_safety,
            cause,
        }
    }

    pub fn compare(x: &Diagnostic, y: &Diagnostic) -> Ordering {
        x.span.cmp(&y.span)
    }
}

/// Store all the diagnoses generated for each `DefId`
pub struct DiagnosticsForDefId {
    pub map: HashMap<DefId, Vec<Diagnostic>>,
}

impl Default for DiagnosticsForDefId {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl DiagnosticsForDefId {
    pub fn insert(&mut self, id: DefId, diags: Vec<Diagnostic>) {
        self.map.insert(id, diags);
    }
}
