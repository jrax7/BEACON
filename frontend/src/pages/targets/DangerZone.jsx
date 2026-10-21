import { useState } from 'react'

import { Card, ConfirmDialog } from '../../components/ui'

export default function DangerZone({ target, onDelete, deleting }) {
  const [pendingDelete, setPendingDelete] = useState(false)

  return (
    <Card
      eyebrow="DANGER ZONE"
      title="Remove target"
      className="target-detail-section danger-zone"
    >
      <p>
        A target can only be removed if it has no scan history. BEACON will refuse deletion when
        historical assessments exist.
      </p>

      <button type="button" className="danger-button" onClick={() => setPendingDelete(true)}>
        Remove target
      </button>

      <ConfirmDialog
        open={pendingDelete}
        title={`Remove ${target.hostname}?`}
        description="This action cannot be undone."
        confirmLabel="Confirm removal"
        busy={deleting}
        onCancel={() => setPendingDelete(false)}
        onConfirm={onDelete}
      />
    </Card>
  )
}
