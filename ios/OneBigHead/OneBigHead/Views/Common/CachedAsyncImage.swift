import SwiftUI

/// A wrapper around AsyncImage that adds basic in-memory caching via NSCache.
struct CachedAsyncImage<Placeholder: View>: View {

    let url: URL?
    let placeholder: () -> Placeholder

    @State private var cachedImage: UIImage?

    // MARK: - Static Cache

    private static var imageCache: NSCache<NSURL, UIImage> {
        CachedAsyncImageCache.shared.cache
    }

    // MARK: - Init

    init(url: URL?, @ViewBuilder placeholder: @escaping () -> Placeholder) {
        self.url = url
        self.placeholder = placeholder
    }

    // MARK: - Body

    var body: some View {
        if let cachedImage {
            Image(uiImage: cachedImage)
                .resizable()
        } else if let url {
            AsyncImage(url: url) { phase in
                switch phase {
                case .success(let image):
                    image
                        .resizable()
                        .onAppear {
                            cacheImage(from: url)
                        }
                case .failure:
                    placeholder()
                case .empty:
                    placeholder()
                @unknown default:
                    placeholder()
                }
            }
            .onAppear {
                if let nsURL = url as NSURL?,
                   let cached = Self.imageCache.object(forKey: nsURL) {
                    cachedImage = cached
                }
            }
        } else {
            placeholder()
        }
    }

    // MARK: - Caching

    private func cacheImage(from url: URL) {
        // Attempt to load data and cache
        Task.detached {
            guard let (data, _) = try? await URLSession.shared.data(from: url),
                  let image = UIImage(data: data) else {
                return
            }
            let nsURL = url as NSURL
            Self.imageCache.setObject(image, forKey: nsURL)
            await MainActor.run {
                cachedImage = image
            }
        }
    }
}

/// Singleton holder for the NSCache to avoid issues with static properties on generic types.
final class CachedAsyncImageCache {
    static let shared = CachedAsyncImageCache()
    let cache: NSCache<NSURL, UIImage> = {
        let cache = NSCache<NSURL, UIImage>()
        cache.countLimit = 100
        return cache
    }()

    private init() {}
}
