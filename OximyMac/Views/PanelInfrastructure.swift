import SwiftUI
import AppKit

// MARK: - Non-activating Panel Infrastructure (Granola / Notion style)

/// Custom NSPanel that accepts mouse clicks without stealing focus from the active app.
class InteractivePanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    override func mouseDown(with event: NSEvent) {
        makeKey()
        super.mouseDown(with: event)
    }
}

/// NSHostingView subclass that ensures first-click works on buttons inside non-key panels.
class FirstClickHostingView<Content: View>: NSHostingView<Content> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        // Remove old tracking areas to prevent accumulation
        for existing in trackingAreas {
            removeTrackingArea(existing)
        }
        // Ensure cursor updates work even when the window isn't key
        let area = NSTrackingArea(
            rect: bounds,
            options: [.mouseEnteredAndExited, .mouseMoved, .activeAlways, .inVisibleRect, .cursorUpdate],
            owner: self,
            userInfo: nil
        )
        addTrackingArea(area)
    }
}
