import SwiftUI

/// A reusable component for editing item properties (key-value pairs).
struct ItemPropertyEditor: View {

    @Binding var properties: [ItemProperty]

    var body: some View {
        ForEach(properties.indices, id: \.self) { index in
            HStack {
                TextField("Key", text: $properties[index].key)
                    .textContentType(.none)
                TextField("Value", text: $properties[index].value)
                    .textContentType(.none)
            }
        }
        .onDelete { indexSet in
            properties.remove(atOffsets: indexSet)
        }

        Button {
            properties.append(ItemProperty(key: "", value: ""))
        } label: {
            Label("Add Property", systemImage: "plus.circle")
        }
    }
}
