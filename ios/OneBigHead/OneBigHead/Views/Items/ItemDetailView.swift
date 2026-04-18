import SwiftUI
import SwiftData

/// Displays full item details.
struct ItemDetailView: View {

    @Environment(\.modelContext) private var modelContext

    @State private var item: LocalItem?
    @State private var showingEditor = false
    @State private var showingDeleteConfirmation = false

    let itemLocalId: UUID
    let collectionLocalId: UUID
    let workspaceId: Int
    let apiClient: APIClient

    var body: some View {
        Group {
            if let item {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        // Image gallery
                        if !item.images.isEmpty {
                            imageGallery(images: item.images)
                        }

                        // Summary
                        if !item.summary.isEmpty {
                            Text(item.summary)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .padding(.horizontal)
                        }

                        // Description
                        if !item.descriptionText.isEmpty {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Description")
                                    .font(.headline)
                                Text(item.descriptionText)
                                    .font(.body)
                            }
                            .padding(.horizontal)
                        }

                        // User flag
                        HStack {
                            Text("Status")
                                .font(.headline)
                            Spacer()
                            Text(userFlagLabel(item.userFlag))
                                .font(.subheadline)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 4)
                                .background(userFlagColor(item.userFlag).opacity(0.15))
                                .foregroundStyle(userFlagColor(item.userFlag))
                                .clipShape(Capsule())
                        }
                        .padding(.horizontal)

                        // Properties
                        if !item.properties.isEmpty {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Properties")
                                    .font(.headline)
                                ForEach(item.properties, id: \.key) { property in
                                    HStack {
                                        Text(property.key)
                                            .font(.subheadline)
                                            .foregroundStyle(.secondary)
                                        Spacer()
                                        Text(property.value)
                                            .font(.subheadline)
                                    }
                                }
                            }
                            .padding(.horizontal)
                        }

                        // Sync status
                        HStack {
                            Spacer()
                            syncStatusView(item.syncStatus)
                            Spacer()
                        }
                        .padding(.horizontal)
                    }
                    .padding(.vertical)
                }
                .navigationTitle(item.name)
                .toolbar {
                    ToolbarItem(placement: .secondaryAction) {
                        Button {
                            showingEditor = true
                        } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                    }
                    ToolbarItem(placement: .secondaryAction) {
                        Button(role: .destructive) {
                            showingDeleteConfirmation = true
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
                .sheet(isPresented: $showingEditor) {
                    let queue = CommandQueue(modelContext: modelContext)
                    let vm = ItemEditorViewModel(
                        modelContext: modelContext,
                        commandQueue: queue,
                        workspaceId: workspaceId,
                        collectionLocalId: collectionLocalId,
                        existingItem: item
                    )
                    ItemEditorView(viewModel: vm) {
                        loadItem()
                    }
                }
                .confirmationDialog("Delete Item", isPresented: $showingDeleteConfirmation) {
                    Button("Delete", role: .destructive) {
                        deleteItem(item)
                    }
                } message: {
                    Text("Are you sure you want to delete this item?")
                }
            } else {
                ContentUnavailableView(
                    "Item Not Found",
                    systemImage: "exclamationmark.triangle"
                )
            }
        }
        .onAppear {
            loadItem()
        }
    }

    // MARK: - Helpers

    private func loadItem() {
        let iid = itemLocalId
        let descriptor = FetchDescriptor<LocalItem>(
            predicate: #Predicate { $0.localId == iid }
        )
        item = try? modelContext.fetch(descriptor).first
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
    }

    @ViewBuilder
    private func imageGallery(images: [ItemImage]) -> some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 12) {
                ForEach(images, id: \.key) { image in
                    if let url = URL(string: image.url) {
                        AsyncImage(url: url) { loadedImage in
                            loadedImage
                                .resizable()
                                .aspectRatio(contentMode: .fill)
                        } placeholder: {
                            Rectangle()
                                .fill(Color.gray.opacity(0.2))
                        }
                        .frame(width: 200, height: 150)
                        .clipped()
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
            }
            .padding(.horizontal)
        }
    }

    @ViewBuilder
    private func syncStatusView(_ status: SyncStatus) -> some View {
        switch status {
        case .synced:
            Label("Synced", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.caption)
        case .pendingCreate, .pendingUpdate:
            Label("Pending sync", systemImage: "icloud.and.arrow.up")
                .foregroundStyle(.orange)
                .font(.caption)
        case .pendingDelete:
            Label("Pending delete", systemImage: "trash.circle")
                .foregroundStyle(.red)
                .font(.caption)
        }
    }

    private func userFlagLabel(_ flag: UserFlag) -> String {
        switch flag {
        case .have: return "Have"
        case .want: return "Want"
        case .tradeOrSell: return "Trade or Sell"
        }
    }

    private func userFlagColor(_ flag: UserFlag) -> Color {
        switch flag {
        case .have: return .green
        case .want: return .blue
        case .tradeOrSell: return .orange
        }
    }
}
