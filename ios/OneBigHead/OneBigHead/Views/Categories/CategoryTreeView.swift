import SwiftUI
import SwiftData

/// Displays categories hierarchically for a collection.
struct CategoryTreeView: View {

    @Environment(\.modelContext) private var modelContext

    @State private var viewModel: CollectionDetailViewModel?
    @State private var showingCategoryEditor = false
    @State private var editingCategory: LocalCategory?

    let collectionLocalId: UUID
    let workspaceId: Int
    let apiClient: APIClient

    var body: some View {
        Group {
            if let viewModel {
                if viewModel.isLoading {
                    ProgressView("Loading...")
                } else {
                    List {
                        let rootCategories = viewModel.categories.filter { $0.parentLocalId == nil }
                        if rootCategories.isEmpty {
                            Text("No categories yet.")
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(rootCategories, id: \.localId) { category in
                                CategoryTreeRow(
                                    category: category,
                                    allCategories: viewModel.categories,
                                    collectionLocalId: collectionLocalId,
                                    workspaceId: workspaceId,
                                    apiClient: apiClient,
                                    depth: 0,
                                    onEdit: { editingCategory = $0 },
                                    onDelete: { viewModel.deleteCategory($0) }
                                )
                            }
                        }
                    }
                }
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Categories")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showingCategoryEditor = true
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Add Category")
            }
        }
        .sheet(isPresented: $showingCategoryEditor) {
            CategoryEditorView(
                categories: viewModel?.categories ?? [],
                collectionLocalId: collectionLocalId
            ) { name, description, parentLocalId in
                viewModel?.createCategory(name: name, description: description, parentLocalId: parentLocalId)
            }
        }
        .sheet(item: $editingCategory) { category in
            CategoryEditorView(
                categories: viewModel?.categories ?? [],
                collectionLocalId: collectionLocalId,
                existingCategory: category
            ) { name, description, parentLocalId in
                viewModel?.updateCategory(category, name: name, description: description)
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

// MARK: - CategoryTreeRow

/// A row displaying a category with its children indented beneath it.
struct CategoryTreeRow: View {
    let category: LocalCategory
    let allCategories: [LocalCategory]
    let collectionLocalId: UUID
    let workspaceId: Int
    let apiClient: APIClient
    let depth: Int
    let onEdit: (LocalCategory) -> Void
    let onDelete: (LocalCategory) -> Void

    var body: some View {
        NavigationLink {
            ItemListView(
                categoryLocalId: category.localId,
                collectionLocalId: collectionLocalId,
                workspaceId: workspaceId,
                apiClient: apiClient
            )
        } label: {
            HStack {
                if depth > 0 {
                    Spacer()
                        .frame(width: CGFloat(depth) * 20)
                }
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
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) {
                onDelete(category)
            } label: {
                Label("Delete", systemImage: "trash")
            }
            Button {
                onEdit(category)
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            .tint(.blue)
        }

        // Render children
        let children = allCategories.filter { $0.parentLocalId == category.localId }
        ForEach(children, id: \.localId) { child in
            CategoryTreeRow(
                category: child,
                allCategories: allCategories,
                collectionLocalId: collectionLocalId,
                workspaceId: workspaceId,
                apiClient: apiClient,
                depth: depth + 1,
                onEdit: onEdit,
                onDelete: onDelete
            )
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

// MARK: - LocalCategory + Identifiable

extension LocalCategory: @retroactive Identifiable {
    var id: UUID { localId }
}
