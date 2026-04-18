import SwiftUI
import SwiftData

/// Displays a grid of collections for the current workspace.
struct CollectionListView: View {

    @Environment(\.modelContext) private var modelContext

    @State private var viewModel: CollectionListViewModel?
    @State private var showingEditor = false

    let workspaceId: Int
    let apiClient: APIClient

    var body: some View {
        NavigationStack {
            Group {
                if let viewModel {
                    if viewModel.isLoading {
                        ProgressView("Loading collections...")
                    } else if viewModel.collections.isEmpty {
                        ContentUnavailableView(
                            "No Collections",
                            systemImage: "folder",
                            description: Text("Tap + to create your first collection.")
                        )
                    } else {
                        ScrollView {
                            LazyVGrid(
                                columns: [GridItem(.adaptive(minimum: 160))],
                                spacing: 16
                            ) {
                                ForEach(viewModel.collections, id: \.localId) { collection in
                                    NavigationLink {
                                        CollectionDetailView(
                                            collectionLocalId: collection.localId,
                                            apiClient: apiClient
                                        )
                                    } label: {
                                        CollectionCardView(collection: collection)
                                    }
                                    .contextMenu {
                                        Button(role: .destructive) {
                                            viewModel.deleteCollection(collection)
                                        } label: {
                                            Label("Delete", systemImage: "trash")
                                        }
                                    }
                                }
                            }
                            .padding()
                        }
                    }
                } else {
                    ProgressView()
                }
            }
            .navigationTitle("Collections")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        showingEditor = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("Add Collection")
                }
            }
            .sheet(isPresented: $showingEditor) {
                if let viewModel {
                    CollectionEditorView(mode: .create) { name, description, slug in
                        viewModel.createCollection(name: name, description: description, slug: slug)
                    }
                }
            }
            .onAppear {
                if viewModel == nil {
                    let queue = CommandQueue(modelContext: modelContext)
                    let vm = CollectionListViewModel(
                        modelContext: modelContext,
                        commandQueue: queue,
                        apiClient: apiClient,
                        workspaceId: workspaceId
                    )
                    viewModel = vm
                }
                viewModel?.loadCollections()
            }
        }
    }
}

// MARK: - CollectionCardView

/// A card displaying a single collection in the grid.
struct CollectionCardView: View {
    let collection: LocalCollection

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Hero image or placeholder
            if let heroUrl = collection.heroImageUrl,
               let url = URL(string: heroUrl) {
                AsyncImage(url: url) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fill)
                } placeholder: {
                    Rectangle()
                        .fill(Color.gray.opacity(0.2))
                }
                .frame(height: 100)
                .clipped()
                .clipShape(RoundedRectangle(cornerRadius: 8))
            } else {
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color.gray.opacity(0.15))
                    .frame(height: 100)
                    .overlay {
                        Image(systemName: "photo")
                            .font(.title2)
                            .foregroundStyle(.secondary)
                    }
            }

            // Name
            Text(collection.name)
                .font(.headline)
                .lineLimit(1)

            // Description
            if !collection.descriptionText.isEmpty {
                Text(collection.descriptionText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            // Sync status
            HStack {
                Spacer()
                syncStatusIcon
            }
        }
        .padding(12)
        .background(Color(.systemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .shadow(color: .black.opacity(0.1), radius: 4, y: 2)
    }

    @ViewBuilder
    private var syncStatusIcon: some View {
        switch collection.syncStatus {
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
