import { Card } from '../../components/ui'
import DangerZone from './DangerZone'

export default function TargetSettings({
  target,
  onDelete,
  deleting,
  readOnly = false,
}) {
  return (
    <div className="target-settings-workspace">
      <Card
        eyebrow="SETTINGS"
        title="Target configuration"
        className="target-detail-section"
      >
        <p className="target-workspace-intro">
          Administrative controls for this registered
          assessment target.
        </p>

        {readOnly && (
          <div className="target-readonly-note">
            <strong>Target deletion is unavailable</strong>
            <p>
              Your current workspace access does not allow
              permanent deletion of this target.
            </p>
          </div>
        )}
      </Card>

      {!readOnly && (
        <DangerZone
          target={target}
          onDelete={onDelete}
          deleting={deleting}
        />
      )}
    </div>
  )
}
