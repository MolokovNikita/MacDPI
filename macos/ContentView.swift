import SwiftUI

struct ContentView: View {
    enum Page {
        case connection, settings
    }

    @ObservedObject var model: AppModel
    @State var page = Page.connection

    var body: some View {
        ZStack(alignment: .bottom) {
            switch page {
            case .connection:
                ConnectionView(model: model)
            case .settings:
                SettingsView(model: model)
            }

            TabBar(selection: $page, items: [
                .init(tab: .connection, title: "Подключение", icon: "power"),
                .init(tab: .settings, title: "Настройки", icon: "gearshape.fill"),
            ])
            .padding(.bottom, 20)
        }
        .frame(minWidth: 400, idealWidth: 420, minHeight: 600, idealHeight: 640)
        .background(WindowBackground().ignoresSafeArea())
        .ignoresSafeArea(edges: .top)
    }
}

// MARK: - Connection

struct ConnectionView: View {
    @ObservedObject var model: AppModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var title: String {
        if model.busy {
            return model.active ? "Отключение…" : "Подключение…"
        }
        return model.active ? "Подключено" : "Не подключено"
    }

    private var subtitle: String {
        if model.busy {
            return model.status
        }
        if model.active || !model.installed {
            return model.detail
        }
        return "Нажмите, чтобы включить обход"
    }

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            PowerButton(model: model)

            Text(title)
                .font(.system(size: 24, weight: .bold))
                .padding(.top, 26)
            Text(subtitle)
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .lineLimit(2)
                .padding(.top, 4)

            if model.hasError && !model.busy {
                Label(model.detail, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(.orange)
                    .multilineTextAlignment(.leading)
                    .textSelection(.enabled)
                    .padding(.top, 12)
            }
            Spacer()

            GroupedSection {
                Toggle(isOn: $model.targetOnly) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Только YouTube и Discord").font(.system(size: 13, weight: .medium))
                        Text(model.active ? "Можно сменить после отключения" : "Остальные сервисы — без обхода")
                            .font(.system(size: 10.5)).foregroundStyle(.secondary)
                    }
                }
                .toggleStyle(.switch)
                .frame(maxWidth: .infinity, alignment: .leading)
                .tint(Color.appTint)
                .disabled(model.active || model.busy)
                .padding(.horizontal, 14).padding(.vertical, 12)
            }.padding(.bottom, 12)

            GroupedSection {
                ServiceRow(model: model, name: "YouTube", host: "www.youtube.com", icon: "play.fill", color: .red)
                RowDivider()
                ServiceRow(model: model, name: "Discord", host: "discord.com",
                           icon: "bubble.left.and.bubble.right.fill", color: Color(red: 0.35, green: 0.4, blue: 0.95))
            }
        }
        .padding(.horizontal, 24)
        .padding(.top, 40)
        .padding(.bottom, 104)
        .animation(reduceMotion ? nil : .easeInOut(duration: 0.25), value: model.active)
        .animation(reduceMotion ? nil : .easeInOut(duration: 0.25), value: model.busy)
    }
}

struct PowerButton: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Button {
            model.toggle()
        } label: {
            ZStack {
                Color.clear
                    .frame(width: 148, height: 148)
                    .glass(cornerRadius: 74, tint: model.active ? .appTint : nil, clear: !model.active)
                if model.busy {
                    ProgressView().controlSize(.large)
                } else {
                    Image(systemName: "power")
                        .font(.system(size: 50, weight: .medium))
                        .foregroundStyle(model.active ? Color.white : Color.primary)
                }
            }
            .contentShape(Circle())
        }
        .buttonStyle(PressScaleStyle())
        .disabled(model.busy)
        .help(model.active ? "Отключить" : "Подключить")
        .accessibilityLabel(model.active ? "Отключить MacDPI" : "Подключить MacDPI")
        .accessibilityValue(model.busy ? "Выполняется" : model.active ? "Подключено" : "Отключено")
    }
}

struct ServiceRow: View {
    @ObservedObject var model: AppModel
    let name: String
    let host: String
    let icon: String
    let color: Color

    private var check: ServiceCheck? {
        model.state?.checks?.first { $0.host == host }
    }

    var body: some View {
        HStack(spacing: 12) {
            IconBadge(symbol: icon, color: color)
            Text(name).font(.system(size: 13.5))
            Spacer()
            status
        }
        .padding(.horizontal, 14)
        .frame(height: 50)
        .help(model.active ? "\(host): \(check?.summary ?? "проверка не выполнялась")" : "")
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private var status: some View {
        if !model.active {
            Text("Не проверено").foregroundStyle(.tertiary)
        } else if let check, check.https != true {
            Label(check.tls && (check.bytes ?? 0) > 0 ? "Обрывается" : "Недоступен", systemImage: "exclamationmark.circle.fill")
                .foregroundStyle(.orange)
        } else {
            Label("Доступен", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        }
    }
}

// MARK: - Settings

struct SettingsView: View {
    private struct Strategy {
        let tag: String
        let title: String
        var note: String?
    }

    private static let strategies = [
        Strategy(tag: "auto", title: "Автоподбор", note: "Рекомендуется"),
        Strategy(tag: "tlsrec-split", title: "TLS-запись + split"),
        Strategy(tag: "multisplit", title: "TLS/TCP split по SNI"),
        Strategy(tag: "tlsrec", title: "TLS-запись"),
        Strategy(tag: "flowseal-general", title: "General", note: "Экспериментальный"),
        Strategy(tag: "flowseal-fake-tls", title: "Fake TLS", note: "Экспериментальный"),
        Strategy(tag: "disorder", title: "Disorder", note: "Экспериментальный"),
    ]

    @ObservedObject var model: AppModel
    @State private var showLog = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text("Настройки")
                    .font(.system(size: 28, weight: .bold))
                    .padding(.horizontal, 4)
                    .padding(.bottom, 18)

                SectionHeader("Режим обхода")
                GroupedSection {
                    ForEach(Self.strategies.indices, id: \.self) { index in
                        if index > 0 {
                            RowDivider(inset: 16)
                        }
                        strategyRow(Self.strategies[index])
                    }
                }
                .disabled(model.active || model.busy)
                SectionFooter(model.active
                              ? "Режим можно сменить после отключения."
                              : "Автоподбор сам проверит YouTube и Discord и выберет подходящий режим.")

                SectionHeader("Обновления обхода")
                GroupedSection {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Профили стратегий").font(.system(size: 13.5))
                            Spacer()
                            Button(model.checkingUpdates ? "Проверяем…" : "Проверить") { model.checkProfileUpdates() }
                                .disabled(model.busy || model.checkingUpdates || !model.installed)
                        }
                        Text(model.state?.profiles?.active ?? "Встроенные профили")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                        if let profiles = model.state?.profiles {
                            if let error = profiles.error, !error.isEmpty {
                                Text("Не удалось обновить: \(error)").font(.system(size: 11)).foregroundStyle(.orange)
                            } else if let available = profiles.available, available != profiles.active {
                                Text("Новый профиль применится при следующем подключении")
                                    .font(.system(size: 11)).foregroundStyle(Color.appTint)
                            }
                            if profiles.upstream_changed {
                                Text("В Flowseal есть новые изменения. Ожидается совместимый профиль для MacDPI.")
                                    .font(.system(size: 11)).foregroundStyle(.secondary)
                            }
                        }
                    }.padding(16)
                }
                SectionFooter("Проверяем автоматически каждые 6 часов. Обновляются только совместимые профили, без перезапуска работающего соединения.")

                SectionHeader("Диагностика")
                GroupedSection {
                    Button {
                        model.saveReport()
                    } label: {
                        RowLabel(title: model.exporting ? "Сохранение…" : "Сохранить отчёт…",
                                 icon: "square.and.arrow.down", color: .blue)
                    }
                    .buttonStyle(.plain)
                    .disabled(model.busy || model.exporting)

                    RowDivider()

                    Button {
                        showLog.toggle()
                    } label: {
                        RowLabel(title: "Журнал событий", icon: "doc.text", color: .gray) {
                            Image(systemName: "chevron.right")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(.tertiary)
                                .rotationEffect(.degrees(showLog ? 90 : 0))
                        }
                    }
                    .buttonStyle(.plain)

                    if showLog {
                        ScrollView {
                            Text(model.events.isEmpty ? "Журнал пуст" : model.events)
                                .font(.system(size: 10.5, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 16)
                                .padding(.bottom, 12)
                        }
                        .frame(height: 150)
                    }
                }
                if let reason = model.state?.packet_error, model.active, !reason.isEmpty {
                    SectionFooter(reason, color: .orange)
                }

                Text("MacDPI \(AppModel.appVersion)")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
                    .frame(maxWidth: .infinity)
                    .padding(.top, 28)
            }
            .padding(.horizontal, 20)
            .padding(.top, 44)
            .padding(.bottom, 110)
        }
        .scrollIndicators(.never)
    }

    private func strategyRow(_ strategy: Strategy) -> some View {
        let selected = model.strategy == strategy.tag
        return Button {
            model.strategy = strategy.tag
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 1) {
                    Text(strategy.title).font(.system(size: 13.5))
                    if let note = strategy.note {
                        Text(note).font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if selected {
                    Image(systemName: "checkmark")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Color.appTint)
                }
            }
            .padding(.horizontal, 16)
            .frame(minHeight: 44)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .opacity(model.active || model.busy ? 0.5 : 1)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

// MARK: - Building blocks

struct GroupedSection<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(spacing: 0) {
            content
        }
        .background(Color.groupedRow, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

struct SectionHeader: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 16)
            .padding(.bottom, 6)
    }
}

struct SectionFooter: View {
    let text: String
    let color: Color?

    init(_ text: String, color: Color? = nil) {
        self.text = text
        self.color = color
    }

    var body: some View {
        Text(text)
            .font(.system(size: 11.5))
            .foregroundStyle(color.map(AnyShapeStyle.init) ?? AnyShapeStyle(.secondary))
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 16)
            .padding(.top, 6)
            .padding(.bottom, 22)
    }
}

struct RowDivider: View {
    var inset: CGFloat = 56

    var body: some View {
        Divider().padding(.leading, inset)
    }
}

struct RowLabel<Accessory: View>: View {
    let title: String
    let icon: String
    let color: Color
    @ViewBuilder var accessory: Accessory

    var body: some View {
        HStack(spacing: 12) {
            IconBadge(symbol: icon, color: color)
            Text(title).font(.system(size: 13.5))
            Spacer()
            accessory
        }
        .padding(.horizontal, 14)
        .frame(height: 48)
        .contentShape(Rectangle())
    }
}

extension RowLabel where Accessory == EmptyView {
    init(title: String, icon: String, color: Color) {
        self.init(title: title, icon: icon, color: color) { EmptyView() }
    }
}

/// A white symbol on a coloured rounded square, as in iOS Settings.
struct IconBadge: View {
    let symbol: String
    let color: Color

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 30, height: 30)
            .background(color.gradient, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

struct PressScaleStyle: ButtonStyle {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.94 : 1)
            .animation(reduceMotion ? nil : .spring(response: 0.3, dampingFraction: 0.6), value: configuration.isPressed)
    }
}
