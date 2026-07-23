use pyo3::{
    exceptions::PyTypeError,
    prelude::*,
    types::{PyAny, PyBytes},
};

fn serialized_bytes(source: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(value) = source.extract::<Vec<u8>>() {
        return Ok(value);
    }
    source.call_method0("to_bytes")?.extract()
}

/// Serialize a native binding object through its rPGP-backed ``to_bytes`` method.
#[pyfunction]
pub(crate) fn serialize(py: Python<'_>, source: &Bound<'_, PyAny>) -> PyResult<Py<PyBytes>> {
    Ok(PyBytes::new(py, &serialized_bytes(source)?).unbind())
}

/// Return the byte length of an object's rPGP serialization.
#[pyfunction(name = "write_len")]
pub(crate) fn serialize_write_len(source: &Bound<'_, PyAny>) -> PyResult<usize> {
    Ok(serialized_bytes(source)?.len())
}

/// Write an object's rPGP serialization to a binary or text-compatible writer.
#[pyfunction(name = "write")]
pub(crate) fn serialize_write(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    writer: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let output = serialized_bytes(source)?;
    match writer.call_method1("write", (PyBytes::new(py, &output),)) {
        Ok(_) => Ok(()),
        Err(error) if error.is_instance_of::<PyTypeError>(py) => {
            let text = std::str::from_utf8(&output).map_err(PyErr::from)?;
            writer.call_method1("write", (text,))?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}
