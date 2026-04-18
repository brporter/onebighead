import SwiftUI

// MARK: - AcceptTermsView

/// Shown when the authenticated user has not yet accepted the terms of service.
struct AcceptTermsView: View {
    let authService: AuthService

    @State private var isAccepting = false

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            VStack(spacing: 16) {
                Image(systemName: "doc.text.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.blue)

                Text("Terms of Service")
                    .font(.title)
                    .fontWeight(.bold)
            }
            .padding(.bottom, 24)

            ScrollView {
                Text(termsText)
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 32)
            }
            .frame(maxHeight: 300)

            Button {
                isAccepting = true
                Task {
                    await authService.acceptTerms()
                    isAccepting = false
                }
            } label: {
                if isAccepting {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                        .frame(height: 50)
                } else {
                    Text("Accept Terms")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .frame(height: 50)
                }
            }
            .buttonStyle(.borderedProminent)
            .padding(.horizontal, 32)
            .padding(.top, 24)
            .disabled(isAccepting)

            if let error = authService.error {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                    .padding(.top, 12)
            }

            Spacer()
        }
    }

    private var termsText: String {
        """
        By using OneBigHead, you agree to the following terms:

        1. You will use the service responsibly and in accordance with applicable laws.

        2. Your content remains yours. We do not claim ownership of any content you upload.

        3. We reserve the right to remove content that violates our policies.

        4. The service is provided as-is without warranties of any kind.

        5. We may update these terms from time to time. Continued use constitutes acceptance.

        Please review the full terms at onebighead.com/terms.
        """
    }
}
