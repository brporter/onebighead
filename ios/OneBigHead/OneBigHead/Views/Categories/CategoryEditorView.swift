import SwiftUI

/// A sheet/form for creating or editing a category.
struct CategoryEditorView: View {

    // MARK: - Properties

    @Environment(\.dismiss) private var dismiss

    @State private var name: String
    @State private var description: String
    @State private var parentLocalId: UUID?

    private let categories: [LocalCategory]
    private let collectionLocalId: UUID
    private let existingCategory: LocalCategory?
    private let onSave: (String, String, UUID?) -> Void

    // MARK: - Init

    init(
        categories: [LocalCategory],
        collectionLocalId: UUID,
        existingCategory: LocalCategory? = nil,
        onSave: @escaping (String, String, UUID?) -> Void
    ) {
        self.categories = categories
        self.collectionLocalId = collectionLocalId
        self.existingCategory = existingCategory
        self.onSave = onSave

        if let existing = existingCategory {
            _name = State(initialValue: existing.name)
            _description = State(initialValue: existing.descriptionText)
            _parentLocalId = State(initialValue: existing.parentLocalId)
        } else {
            _name = State(initialValue: "")
            _description = State(initialValue: "")
            _parentLocalId = State(initialValue: nil)
        }
    }

    // MARK: - Body

    var body: some View {
        NavigationStack {
            Form {
                Section("Category Details") {
                    TextField("Name", text: $name)
                    TextField("Description", text: $description)
                }

                Section("Parent Category") {
                    Picker("Parent", selection: $parentLocalId) {
                        Text("None").tag(UUID?.none)
                        ForEach(availableParents, id: \.localId) { category in
                            Text(category.name).tag(Optional(category.localId))
                        }
                    }
                }
            }
            .navigationTitle(existingCategory != nil ? "Edit Category" : "New Category")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        onSave(name, description, parentLocalId)
                        dismiss()
                    }
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }

    // MARK: - Helpers

    /// Categories available as parents (exclude self to prevent cycles).
    private var availableParents: [LocalCategory] {
        if let existing = existingCategory {
            return categories.filter { $0.localId != existing.localId }
        }
        return categories
    }
}
