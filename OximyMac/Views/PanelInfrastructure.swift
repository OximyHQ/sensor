import SwiftUI
import AppKit

// MARK: - Non-activating Panel Infrastructure (Granola / Notion style)

/// Custom NSPanel that accepts mouse clicks without stealing focus from the active app.
class InteractivePanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    /// Make the panel key *before* the event reaches any SwiftUI view,
    /// so buttons recognise the click on the very first press.
    override func sendEvent(_ event: NSEvent) {
        if event.type == .leftMouseDown {
            makeKey()
        }
        super.sendEvent(event)
    }
}

/// NSHostingView subclass that ensures first-click works on buttons inside non-key panels.
class FirstClickHostingView<Content: View>: NSHostingView<Content> {
    /// Tag used to identify our custom tracking area so we only remove it, not SwiftUI's.
    private var customTrackingArea: NSTrackingArea?

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func updateTrackingAreas() {
        // Remove only our custom tracking area — leave SwiftUI's internal ones intact
        if let old = customTrackingArea {
            removeTrackingArea(old)
        }
        super.updateTrackingAreas()
        // Ensure cursor updates work even when the window isn't key
        let area = NSTrackingArea(
            rect: bounds,
            options: [.mouseEnteredAndExited, .mouseMoved, .activeAlways, .inVisibleRect, .cursorUpdate],
            owner: self,
            userInfo: nil
        )
        addTrackingArea(area)
        customTrackingArea = area
    }
}
