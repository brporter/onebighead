import SwiftUI

/// A sheet/form for creating or editing a collection.
struct CollectionEditorView: View {

    // MARK: - Mode

    enum Mode {
        case create
        case edit(name: String, description: String, slug: String)
    }

    // MARK: - Properties

    @Environment(\.dismiss) private var dismiss

    @State private var name: String
    @State private var description: String
    @State private var slug: String

    private let mode: Mode
    private let onSave: (String, String, String) -> Void

    // MARK: - Init

    init(mode: Mode, onSave: @escaping (String, String, String) -> Void) {
        self.mode = mode
        self.onSave = onSave
        switch mode {
        case .create:
            _name = State(initialValue: "")
            _description = State(initialValue: "")
            _slug = State(initialValue: "")
        case .edit(let name, let description, let slug):
            _name = State(initialValue: name)
            _description = State(initialValue: description)
            _slug = State(initialValue: slug)
        }
    }

    // MARK: - Body

    var body: some View {
        NavigationStack {
            Form {
                Section("Collection Details") {
                    TextField("Name", text: $name)
                        .onChange(of: name) { _, newValue in
                            slug = generateSlug(from: newValue)
                        }
                    TextField("Description", text: $description)
                }
                Section("Slug") {
                    Text(slug)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle(navigationTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        onSave(name, description, slug)
                        dismiss()
                    }
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }

    // MARK: - Helpers

    private var navigationTitle: String {
        switch mode {
        case .create:
            return "New Collection"
        case .edit:
            return "Edit Collection"
        }
    }

    /// Auto-generates a slug from the name: lowercased, spaces to hyphens, non-alphanumeric stripped.
    static func generateSlug(from name: String) -> String {
        let lowered = name.lowercased()
        let spacesToHyphens = lowered.replacingOccurrences(of: " ", with: "-")
        let filtered = spacesToHyphens.unicodeScalars.filter { scalar in
            CharacterSet.alphanumerics.contains(scalar) || scalar == "-"
        }
        return String(String.UnicodeScalarView(filtered))
    }

    private func generateSlug(from name: String) -> String {
        Self.generateSlug(from: name)
    }
}
