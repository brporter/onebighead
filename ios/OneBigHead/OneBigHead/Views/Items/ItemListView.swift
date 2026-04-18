import SwiftUI
import SwiftData

/// Displays items in a category.
struct ItemListView: View {

    @Environment(\.modelContext) private var modelContext

    @State private var items: [LocalItem] = []
    @State private var showingItemEditor = false
    @State private var category: LocalCategory?

    let categoryLocalId: UUID
    let collectionLocalId: UUID
    let workspaceId: Int
    let apiClient: APIClient

    var body: some View {
        Group {
            if items.isEmpty {
                ContentUnavailableView(
                    "No Items",
                    systemImage: "tray",
                    description: Text("Tap + to add your first item.")
                )
            } else {
                List {
                    ForEach(items, id: \.localId) { item in
                        NavigationLink {
                            ItemDetailView(
                                itemLocalId: item.localId,
                                collectionLocalId: collectionLocalId,
                                workspaceId: workspaceId,
                                apiClient: apiClient
                            )
                        } label: {
                            ItemRowView(item: item)
                        }
                    }
                    .onDelete { indexSet in
                        for index in indexSet {
                            deleteItem(items[index])
                        }
                    }
                }
            }
        }
        .navigationTitle(category?.name ?? "Items")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showingItemEditor = true
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Add Item")
            }
        }
        .sheet(isPresented: $showingItemEditor) {
            ItemEditorSheet(
                modelContext: modelContext,
                workspaceId: workspaceId,
                collectionLocalId: collectionLocalId,
                categoryLocalId: categoryLocalId
            ) {
                loadItems()
            }
        }
        .onAppear {
            loadItems()
            loadCategory()
        }
    }

    // MARK: - Helpers

    private func loadItems() {
        let catId = categoryLocalId
        let descriptor = FetchDescriptor<LocalItem>(
            predicate: #Predicate { $0.categoryLocalId == catId },
            sortBy: [SortDescriptor(\.name, order: .forward)]
        )
        do {
            items = try modelContext.fetch(descriptor).filter { $0.syncStatus != .pendingDelete }
        } catch {
            items = []
        }
    }

    private func loadCategory() {
        let catId = categoryLocalId
        let descriptor = FetchDescriptor<LocalCategory>(
            predicate: #Predicate { $0.localId == catId }
        )
        category = try? modelContext.fetch(descriptor).first
    }

    private func deleteItem(_ item: LocalItem) {
        let queue = CommandQueue(modelContext: modelContext)
        item.syncStatus = .pendingDelete

        do {
            try queue.enqueue(
                entityType: "Item",
                operation: "Delete",
                entityLocalId: item.localId,
                payload: EmptyPayload()
            )
        } catch {
            // Error is silently handled
        }

        loadItems()
    }
}

// MARK: - ItemRowView

/// A row displaying a single item in the list.
struct ItemRowView: View {
    let item: LocalItem

    var body: some View {
        HStack(spacing: 12) {
            // Primary image thumbnail
            if let primaryImage = item.images.first(where: { $0.isPrimary }) ?? item.images.first,
               let url = URL(string: primaryImage.url) {
                AsyncImage(url: url) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fill)
                } placeholder: {
                    Rectangle()
                        .fill(Color.gray.opacity(0.2))
                }
                .frame(width: 44, height: 44)
                .clipped()
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(item.name)
                    .font(.body)
                if !item.summary.isEmpty {
                    Text(item.summary)
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
        switch item.syncStatus {
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

// MARK: - ItemEditorSheet

/// A wrapper that presents ItemEditorView in a sheet with its own ViewModel.
struct ItemEditorSheet: View {

    @Environment(\.dismiss) private var dismiss

    let modelContext: ModelContext
    let workspaceId: Int
    let collectionLocalId: UUID
    let categoryLocalId: UUID
    let onSaved: () -> Void

    var body: some View {
        let queue = CommandQueue(modelContext: modelContext)
        let vm = ItemEditorViewModel(
            modelContext: modelContext,
            commandQueue: queue,
            workspaceId: workspaceId,
            collectionLocalId: collectionLocalId
        )
        ItemEditorView(viewModel: vm, initialCategoryLocalId: categoryLocalId) {
            onSaved()
            dismiss()
        }
    }
}
