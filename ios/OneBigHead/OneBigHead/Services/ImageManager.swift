import UIKit
import SwiftData

/// Manages local image storage and preparation for upload.
final class ImageManager: ImageManaging {

    // MARK: - Constants

    static let pendingImagesDirectory = "pending_images"
    static let defaultMaxDimension: CGFloat = 2048
    static let defaultCompressionQuality: CGFloat = 0.8

    // MARK: - Directory Helpers

    /// Returns the URL for the pending images directory, creating it if needed.
    static func pendingImagesDirectoryURL() throws -> URL {
        let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let directoryURL = documentsURL.appendingPathComponent(pendingImagesDirectory)
        if !FileManager.default.fileExists(atPath: directoryURL.path) {
            try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        }
        return directoryURL
    }

    // MARK: - Image Resizing

    /// Resizes an image so its longest edge does not exceed `maxDimension`.
    /// If the image is already smaller, it is returned unchanged.
    static func resizeImage(_ image: UIImage, maxDimension: CGFloat = defaultMaxDimension) -> UIImage {
        let size = image.size
        let longestEdge = max(size.width, size.height)

        guard longestEdge > maxDimension else {
            return image
        }

        let scale = maxDimension / longestEdge
        let newSize = CGSize(
            width: (size.width * scale).rounded(.down),
            height: (size.height * scale).rounded(.down)
        )

        let renderer = UIGraphicsImageRenderer(size: newSize)
        return renderer.image { _ in
            image.draw(in: CGRect(origin: .zero, size: newSize))
        }
    }

    // MARK: - Save

    /// Resizes the image, saves it as JPEG, and creates a `LocalPendingImage` record.
    func saveImage(
        _ image: UIImage,
        for itemLocalId: UUID,
        in modelContext: ModelContext,
        maxDimension: CGFloat = defaultMaxDimension,
        compressionQuality: CGFloat = defaultCompressionQuality
    ) throws -> LocalPendingImage {
        let resized = Self.resizeImage(image, maxDimension: maxDimension)

        guard let jpegData = resized.jpegData(compressionQuality: compressionQuality) else {
            throw ImageManagerError.jpegConversionFailed
        }

        let fileId = UUID()
        let directoryURL = try Self.pendingImagesDirectoryURL()
        let fileURL = directoryURL.appendingPathComponent("\(fileId).jpg")

        try jpegData.write(to: fileURL, options: .atomic)

        let pendingImage = LocalPendingImage(
            localFilePath: fileURL.path,
            itemLocalId: itemLocalId
        )
        modelContext.insert(pendingImage)

        return pendingImage
    }

    // MARK: - Load

    /// Loads a UIImage from the local file path of a pending image.
    func loadImage(for pendingImage: LocalPendingImage) -> UIImage? {
        UIImage(contentsOfFile: pendingImage.localFilePath)
    }

    // MARK: - Raw Data

    /// Returns the raw JPEG data for a pending image.
    func imageData(for pendingImage: LocalPendingImage) -> Data? {
        FileManager.default.contents(atPath: pendingImage.localFilePath)
    }

    /// Returns the raw JPEG data for a pending image (ImageManaging protocol).
    func loadImageData(for pendingImage: LocalPendingImage) -> Data? {
        imageData(for: pendingImage)
    }

    // MARK: - Delete

    /// Deletes the local file and removes the SwiftData record.
    func deleteLocalImage(_ pendingImage: LocalPendingImage, in modelContext: ModelContext) {
        let path = pendingImage.localFilePath
        if FileManager.default.fileExists(atPath: path) {
            try? FileManager.default.removeItem(atPath: path)
        }
        modelContext.delete(pendingImage)
    }

    // MARK: - Cleanup

    /// Removes local files and records for images that have been successfully uploaded.
    func cleanupUploadedImages(in modelContext: ModelContext) throws {
        let descriptor = FetchDescriptor<LocalPendingImage>()
        let allImages = try modelContext.fetch(descriptor)
        let uploadedImages = allImages.filter { $0.uploadStatus == .uploaded }

        for image in uploadedImages {
            let path = image.localFilePath
            if FileManager.default.fileExists(atPath: path) {
                try? FileManager.default.removeItem(atPath: path)
            }
            modelContext.delete(image)
        }
    }
}

// MARK: - Errors

enum ImageManagerError: Error, LocalizedError {
    case jpegConversionFailed

    var errorDescription: String? {
        switch self {
        case .jpegConversionFailed:
            return "Failed to convert image to JPEG format."
        }
    }
}
