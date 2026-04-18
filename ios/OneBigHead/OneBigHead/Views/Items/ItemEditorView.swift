import SwiftUI
import SwiftData

/// A form for creating or editing an item.
struct ItemEditorView: View {

    @Environment(\.dismiss) private var dismiss
    @Environment(\.modelContext) private var modelContext

    @State var viewModel: ItemEditorViewModel
    let initialCategoryLocalId: UUID?
    let onSaved: (() -> Void)?

    @State private var showImageSourceSheet = false
    @State private var showCamera = false
    @State private var pendingImages: [LocalPendingImage] = []
    @State private var pendingThumbnails: [UUID: UIImage] = [:]

    private let imageManager = ImageManager()

    // MARK: - Init

    init(viewModel: ItemEditorViewModel, initialCategoryLocalId: UUID? = nil, onSaved: (() -> Void)? = nil) {
        self._viewModel = State(initialValue: viewModel)
        self.initialCategoryLocalId = initialCategoryLocalId
        self.onSaved = onSaved
    }

    // MARK: - Body

    var body: some View {
        NavigationStack {
            Form {
                Section("Item Details") {
                    TextField("Name", text: $viewModel.name)
                    TextField("Summary", text: $viewModel.summary)
                    TextEditor(text: $viewModel.descriptionText)
                        .frame(minHeight: 80)
                }

                Section("Status") {
                    Picker("Flag", selection: $viewModel.userFlag) {
                        Text("Have").tag(UserFlag.have)
                        Text("Want").tag(UserFlag.want)
                        Text("Trade or Sell").tag(UserFlag.tradeOrSell)
                    }
                }

                Section("Properties") {
                    ItemPropertyEditor(properties: $viewModel.properties)
                }

                Section("Images") {
                    // Server images
                    if !viewModel.images.isEmpty {
                        ForEach(viewModel.images, id: \.key) { image in
                            HStack {
                                if let url = URL(string: image.url) {
                                    CachedAsyncImage(url: url) {
                                        Rectangle()
                                            .fill(Color.gray.opacity(0.2))
                                    }
                                    .aspectRatio(contentMode: .fill)
                                    .frame(width: 44, height: 44)
                                    .clipped()
                                    .clipShape(RoundedRectangle(cornerRadius: 6))
                                }
                                Text(image.isPrimary ? "Primary" : "Image")
                                    .font(.caption)
                            }
                        }
                        .onDelete { offsets in
                            viewModel.images.remove(atOffsets: offsets)
                        }
                    }

                    // Pending local images
                    if !pendingImages.isEmpty {
                        ForEach(pendingImages, id: \.localId) { pending in
                            HStack {
                                if let thumb = pendingThumbnails[pending.localId] {
                                    Image(uiImage: thumb)
                                        .resizable()
                                        .aspectRatio(contentMode: .fill)
                                        .frame(width: 44, height: 44)
                                        .clipped()
                                        .clipShape(RoundedRectangle(cornerRadius: 6))
                                } else {
                                    Rectangle()
                                        .fill(Color.gray.opacity(0.2))
                                        .frame(width: 44, height: 44)
                                        .clipShape(RoundedRectangle(cornerRadius: 6))
                                }
                                Text("Pending Upload")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .onDelete { offsets in
                            deletePendingImages(at: offsets)
                        }
                    }

                    if viewModel.images.isEmpty && pendingImages.isEmpty {
                        Text("No images yet.")
                            .foregroundStyle(.secondary)
                    }

                    Button("Add Photo") {
                        showImageSourceSheet = true
                    }
                }

                if let error = viewModel.errorMessage {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.caption)
                    }
                }
            }
            .navigationTitle(viewModel.isEditing ? "Edit Item" : "New Item")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        if let catId = initialCategoryLocalId, viewModel.categoryLocalId == nil {
                            viewModel.categoryLocalId = catId
                        }
                        viewModel.save()
                        onSaved?()
                        dismiss()
                    }
                    .disabled(viewModel.name.trimmingCharacters(in: .whitespaces).isEmpty || viewModel.isSaving)
                }
            }
            .confirmationDialog("Add Photo", isPresented: $showImageSourceSheet, titleVisibility: .visible) {
                if UIImagePickerController.isSourceTypeAvailable(.camera) {
                    Button("Take Photo") {
                        showCamera = true
                    }
                }
                LibraryImagePicker { image in
                    handleCapturedImage(image)
                }
            }
            .fullScreenCover(isPresented: $showCamera) {
                CameraImagePicker { image in
                    handleCapturedImage(image)
                }
                .ignoresSafeArea()
            }
            .onAppear {
                if let catId = initialCategoryLocalId, viewModel.categoryLocalId == nil, !viewModel.isEditing {
                    viewModel.categoryLocalId = catId
                }
                loadPendingImages()
            }
        }
    }

    // MARK: - Image Handling

    private func handleCapturedImage(_ image: UIImage) {
        guard let itemLocalId = viewModel.existingItem?.localId ?? viewModel.existingItem?.localId else {
            // For new items, save first so we have a localId
            return
        }

        do {
            let pending = try imageManager.saveImage(image, for: itemLocalId, in: modelContext)
            pendingImages.append(pending)
            if let thumb = imageManager.loadImage(for: pending) {
                pendingThumbnails[pending.localId] = thumb
            }
        } catch {
            viewModel.errorMessage = "Failed to save image: \(error.localizedDescription)"
        }
    }

    private func loadPendingImages() {
        guard let itemLocalId = viewModel.existingItem?.localId else { return }

        let predicate = #Predicate<LocalPendingImage> { $0.itemLocalId == itemLocalId }
        var descriptor = FetchDescriptor(predicate: predicate)
        descriptor.fetchLimit = 100

        if let images = try? modelContext.fetch(descriptor) {
            pendingImages = images
            for img in images {
                if let thumb = imageManager.loadImage(for: img) {
                    pendingThumbnails[img.localId] = thumb
                }
            }
        }
    }

    private func deletePendingImages(at offsets: IndexSet) {
        for index in offsets {
            let pending = pendingImages[index]
            imageManager.deleteLocalImage(pending, in: modelContext)
            pendingThumbnails.removeValue(forKey: pending.localId)
        }
        pendingImages.remove(atOffsets: offsets)
    }
}
