import { Link } from 'react-router'

import {
  StatusBadge,
} from '../../components/ui'
import { formatDate } from '../../lib/format'
import {
  findingDetailPath,
} from './helpers'


function classificationLabel(value) {
  return String(value || 'unknown')
    .replaceAll('_', ' ')
}


function shortId(value) {
  const text = String(value || '')

  if (!text) {
    return '—'
  }

  return text.slice(0, 8)
}


function sourceTools(sources = []) {
  return sources
    .map((source) => source.tool_name)
    .filter(Boolean)
}


export default function FindingsTable({
  items,
}) {
  return (
    <div className="findings-table-wrapper">
      <table className="findings-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Finding</th>
            <th>Classification</th>
            <th>Confidence</th>
            <th>Target</th>
            <th>Assessment</th>
            <th>Sources</th>
            <th>Occurrences</th>
            <th>Last observed</th>
          </tr>
        </thead>

        <tbody>
          {items.map((item) => {
            const tools = sourceTools(
              item.sources,
            )

            return (
              <tr key={item.id}>
                <td>
                  <StatusBadge
                    value={item.severity}
                  />
                </td>

                <td>
                  <div className="findings-title-cell">
                    <strong>
                      <Link
                        to={findingDetailPath(item.id)}
                      >
                        {item.title}
                      </Link>
                    </strong>

                    {item.cwe_id && (
                      <span>{item.cwe_id}</span>
                    )}
                  </div>
                </td>

                <td>
                  <span className="findings-classification">
                    {classificationLabel(
                      item.classification,
                    )}
                  </span>
                </td>

                <td>
                  {item.confidence || '—'}
                </td>

                <td>
                  <Link
                    className="findings-context-link"
                    to={`/targets/${item.target_id}`}
                  >
                    {item.target_hostname}
                  </Link>
                </td>

                <td>
                  <Link
                    className="findings-context-link"
                    to={`/scans/${item.scan_id}`}
                    title={item.scan_id}
                  >
                    {shortId(item.scan_id)}
                  </Link>
                </td>

                <td>
                  <div className="findings-source-list">
                    {tools.length > 0
                      ? tools.map((tool) => (
                        <span
                          className="findings-source"
                          key={tool}
                        >
                          {tool}
                        </span>
                      ))
                      : '—'}
                  </div>
                </td>

                <td>
                  {item.occurrence_count}
                </td>

                <td>
                  {formatDate(
                    item.last_observed_at,
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
