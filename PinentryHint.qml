import QtQuick
import qs.Commons
import qs.Ui

// Where a form's master password (and, for the PIN form, the new PIN) is
// typed when pinentry takes it instead of the form's own fields: a caption in
// their place, a wait while the vault helper pinentry runs under is not up,
// and after a pinentry failure the notice with the panel's field offered by
// choice (declinePinentry() in Service.qml; never remembered). The form shows
// its fields only while `vault.typedSecretEntry` is "field"; this is drawn
// otherwise, and with the notice alone when the fields are shown because
// pinentry is missing or was declined.
Column {
  id: hint

  required property var panel
  required property var vault
  // What the fields would have taken, e.g. "master password".
  required property string what
  property bool busy: false

  readonly property bool typesHere: hint.vault.typedSecretEntry === "field"
  readonly property string notice: String(hint.vault.pinentryNotice || "")

  visible: !typesHere || notice !== ""
  width: parent ? parent.width : 0
  spacing: Style.space(6)

  Text {
    textFormat: Text.PlainText
    visible: hint.vault.pinentryAvailable && hint.notice === ""
    width: parent.width
    text: "Your " + hint.what + " is typed in a separate window, not in this panel."
    color: hint.panel.dim
    font.family: hint.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  Text {
    textFormat: Text.PlainText
    visible: hint.vault.typedSecretWaits
    width: parent.width
    text: "Your " + hint.what + " is typed in a separate window once the vault helper is running."
    color: hint.panel.dim
    font.family: hint.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  Text {
    textFormat: Text.PlainText
    visible: hint.notice !== ""
    width: parent.width
    text: hint.notice
    color: hint.panel.dim
    font.family: hint.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  Button {
    visible: hint.vault.pinentryAvailable && hint.notice !== ""
    width: parent.width
    text: "Type it here instead"
    iconText: "󰌌"
    fontFamily: hint.panel.fontFamily
    enabled: !hint.busy
    onClicked: hint.vault.declinePinentry()
  }
}
