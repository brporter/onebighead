import SwiftUI
import SwiftData

/// Displays a single collection's categories and details.
struct CollectionDetailView: View {

    @Environment(\.modelContext) private var modelContext

    @State private var viewModel: CollectionDetailViewModel?
    @State private var showingCategoryEditor = false
    @State private var showingCollectionEditor = false

    let collectionLocalId: UUID
    let apiClient: APIClient

    var body: some View {
        Group {
            if let viewModel {
                if viewModel.isLoading {
                    ProgressView("Loading...")
                } else if let collection = viewModel.collection {
                    List {
                        // Collection info section
                        if !collection.descriptionText.isEmpty {
                            Section("About") {
                                Text(collection.descriptionText)
                                    .font(.body)
                                    .foregroundStyle(.secondary)
                            }
                        }

                        // Categories section
                        Section("Categories") {
                            if viewModel.categories.isEmpty {
                                Text("No categories yet.")
                                    .foregroundStyle(.secondary)
                            } else {
                                ForEach(viewModel.categories, id: \.localId) { category in
                                    CategoryRowView(category: category)
                                }
                                .onDelete { indexSet in
                                    for index in indexSet {
                                        let category = viewModel.categories[index]
                                        viewModel.deleteCategory(category)
                                    }
                                }
                            }
                        }
                    }
                    .navigationTitle(collection.name)
                    .toolbar {
                        ToolbarItem(placement: .primaryAction) {
                            Button {
                                showingCategoryEditor = true
                            } label: {
                                Image(systemName: "plus")
                            }
                            .accessibilityLabel("Add Category")
                        }
                        ToolbarItem(placement: .secondaryAction) {
                            Button {
                                showingCollectionEditor = true
                            } label: {
                                Label("Edit", systemImage: "pencil")
                            }
                        }
                    }
                    .sheet(isPresented: $showingCategoryEditor) {
                        CategoryEditorSheet { name, description in
                            viewModel.createCategory(name: name, description: description, parentLocalId: nil)
                        }
                    }
                    .sheet(isPresented: $showingCollectionEditor) {
                        CollectionEditorView(
                            mode: .edit(
                                name: collection.name,
                                description: collection.descriptionText,
                                slug: collection.slug
                            )
                        ) { name, description, _ in
                            viewModel.updateCollection(collection, name: name, description: description)
                        }
                    }
                } else {
                    ContentUnavailableView(
                        "Collection Not Found",
                        systemImage: "exclamationmark.triangle"
                    )
                }
            } else {
                ProgressView()
            }
        }
        .onAppear {
            if viewModel == nil {
                let queue = CommandQueue(modelContext: modelContext)
                let vm = CollectionDetailViewModel(
                    modelContext: modelContext,
                    commandQueue: queue,
                    apiClient: apiClient,
                    collectionLocalId: collectionLocalId
                )
                viewModel = vm
            }
            viewModel?.loadData()
        }
    }
}

// MARK: - CategoryRowView

/// A row displaying a single category in the list.
struct CategoryRowView: View {
    let category: LocalCategory

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(category.name)
                    .font(.body)
                if !category.descriptionText.isEmpty {
                    Text(category.descriptionText)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer()
            syncStatusIcon
        }
    }

    @ViewBuilder
    private var syncStatusIcon: some View {
        switch category.syncStatus {
        case .synced:
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.caption)
        case .pendingCreate, .pendingUpdate:
            Image(systemName: "icloud.and.arrow.up")
                .foregroundStyle(.orange)
                .font(.caption)
        case .pendingDelete:
            Image(systemName: "trash.circle")
                .foregroundStyle(.red)
                .font(.caption)
        }
    }
}

// MARK: - CategoryEditorSheet

/// A simple sheet for creating a category.
struct CategoryEditorSheet: View {

    @Environment(\.dismiss) private var dismiss

    @State private var name: String = ""
    @State private var description: String = ""

    let onSave: (String, String) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section("Category Details") {
                    TextField("Name", text: $name)
                    TextField("Description", text: $description)
                }
            }
            .navigationTitle("New Category")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        onSave(name, description)
                        dismiss()
                    }
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }
}
