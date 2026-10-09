#ifdef AERORE_HAS_PYBIND

#include "aerore/session.hpp"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;

PYBIND11_MODULE(aerore, m) {
    m.doc() = "AeroRE scripting. Breakpoint conditions, batch analysis, unpacking.";

    py::class_<aerore::Function>(m, "Function")
        .def_readonly("start", &aerore::Function::start)
        .def_readonly("end", &aerore::Function::end)
        .def_readonly("name", &aerore::Function::name);

    py::class_<aerore::Session>(m, "Session")
        .def(py::init<>())
        .def("load", [](aerore::Session& s, const std::string& path, bool unpack) { s.load_file(path, unpack); },
             py::arg("path"), py::arg("auto_unpack") = true)
        .def("save_db", &aerore::Session::save_db)
        .def("open_db", &aerore::Session::open_db)
        .def("set_name", &aerore::Session::set_name)
        .def("set_comment", &aerore::Session::set_comment)
        .def("query", &aerore::Session::query)
        .def("functions", [](aerore::Session& s) {
            auto model = s.model();
            return model ? model->functions : std::vector<aerore::Function>{};
        })
        .def("disasm", [](aerore::Session& s, aerore::u64 va, int count) {
            std::vector<std::string> lines;
            auto model = s.model();
            if (!model) return lines;
            for (int i = 0; i < count; ++i) {
                auto it = model->insns.find(va);
                if (it == model->insns.end()) break;
                lines.push_back(aerore::hex(va) + " " + it->second.text);
                va += it->second.len ? it->second.len : 1;
            }
            return lines;
        })
        .def("xrefs_to", [](aerore::Session& s, aerore::u64 va) {
            auto model = s.model();
            return model ? model->xrefs_to(va) : std::vector<aerore::Xref>{};
        })
        .def("fix_iat_json", [](aerore::Session& s, const std::string& modules_json, bool patch) {
            auto report = s.fix_iat(aerore::modules_from_json(modules_json), patch);
            return report.message;
        })
        .def("unpack", [](aerore::Session& s) {
            auto r = s.unpack_best();
            return r.log;
        });

    py::class_<aerore::Xref>(m, "Xref")
        .def_readonly("src", &aerore::Xref::src)
        .def_readonly("dst", &aerore::Xref::dst);
}

#endif
