import SwiftUI

/// A floating tab bar in the style of iOS 26: a glass capsule whose selection turns into
/// a clear glass lens while it is pressed or dragged.
struct TabBar<Tab: Hashable>: View {
    struct Item {
        let tab: Tab
        let title: String
        let icon: String
    }

    @Binding var selection: Tab
    let items: [Item]

    @State private var dragLocation: CGFloat?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private let itemWidth: CGFloat = 92
    private let height: CGFloat = 58
    private let inset: CGFloat = 4

    private var selectedIndex: Int {
        items.firstIndex { $0.tab == selection } ?? 0
    }

    var body: some View {
        ZStack(alignment: .leading) {
            Capsule()
                .fill(Color.primary.opacity(0.09))
                .frame(width: itemWidth, height: height - inset * 2)
                .offset(x: CGFloat(selectedIndex) * itemWidth)
                .opacity(dragLocation == nil ? 1 : 0)

            HStack(spacing: 0) {
                ForEach(items.indices, id: \.self) { index in
                    label(for: items[index], selected: index == selectedIndex)
                }
            }

            if let dragLocation {
                Color.clear
                    .frame(width: itemWidth + 14, height: height + 8)
                    .glass(cornerRadius: (height + 8) / 2, clear: true)
                    .offset(x: lensOffset(dragLocation))
                    .transition(.scale(scale: 0.8).combined(with: .opacity))
                    .allowsHitTesting(false)
            }
        }
        .frame(height: height - inset * 2)
        .padding(inset)
        .glass(cornerRadius: height / 2)
        .contentShape(Capsule())
        .gesture(
            DragGesture(minimumDistance: 0)
                .onChanged { value in
                    withAnimation(reduceMotion ? nil : .spring(response: 0.3, dampingFraction: 0.75)) {
                        dragLocation = value.location.x - inset
                        selection = items[index(at: value.location.x - inset)].tab
                    }
                }
                .onEnded { value in
                    withAnimation(reduceMotion ? nil : .spring(response: 0.35, dampingFraction: 0.8)) {
                        selection = items[index(at: value.location.x - inset)].tab
                        dragLocation = nil
                    }
                }
        )
        .accessibilityRepresentation {
            Picker("Раздел", selection: $selection) {
                ForEach(items.indices, id: \.self) { index in
                    Text(items[index].title).tag(items[index].tab)
                }
            }
            .pickerStyle(.segmented)
        }
    }

    private func label(for item: Item, selected: Bool) -> some View {
        VStack(spacing: 3) {
            Image(systemName: item.icon)
                .font(.system(size: 19, weight: .medium))
                .frame(height: 22)
            Text(item.title)
                .font(.system(size: 10.5, weight: .semibold))
        }
        .foregroundStyle(selected ? Color.appTint : Color.primary.opacity(0.75))
        .frame(width: itemWidth, height: height - inset * 2)
    }

    private func index(at x: CGFloat) -> Int {
        min(max(Int(x / itemWidth), 0), items.count - 1)
    }

    private func lensOffset(_ x: CGFloat) -> CGFloat {
        let width = itemWidth + 14
        let range = -7...(CGFloat(items.count) * itemWidth - width + 7)
        return min(max(x - width / 2, range.lowerBound), range.upperBound)
    }
}
