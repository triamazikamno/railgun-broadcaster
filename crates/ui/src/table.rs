use gpui::Pixels;
use gpui_component::table::Column;

/// Shared helper for delegates that store their column descriptors locally and
/// need to mirror runtime drag widths back into that stored state.
pub trait ColumnWidthSync {
    fn columns_mut(&mut self) -> &mut [Column];

    fn apply_column_widths(&mut self, widths: &[Pixels]) {
        for (col, width) in self.columns_mut().iter_mut().zip(widths.iter()) {
            col.width = *width;
        }
    }
}
