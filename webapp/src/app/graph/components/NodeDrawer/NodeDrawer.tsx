'use client'

import { useState } from 'react'
import { Drawer } from '@/components/ui'
import { GraphNode } from '../../types'
import { getNodeColor } from '../../utils'
import { formatPropertyValue } from '../../utils/formatters'
import styles from './NodeDrawer.module.css'

interface NodeDrawerProps {
  node: GraphNode | null
  isOpen: boolean
  onClose: () => void
  onDeleteNode?: (nodeId: string) => Promise<void>
}

export function NodeDrawer({ node, isOpen, onClose, onDeleteNode }: NodeDrawerProps) {
  const [isDeleting, setIsDeleting] = useState(false)

  const handleDelete = async () => {
    if (!node || !onDeleteNode) return
    if (!confirm('Delete this Exploit node and all its connections?')) return
    setIsDeleting(true)
    try {
      await onDeleteNode(node.id)
      onClose()
    } finally {
      setIsDeleting(false)
    }
  }

  // Filter out internal IDs and sort with timestamps at the bottom
  const hiddenKeys = ['project_id', 'user_id']
  const sortedProperties = node
    ? Object.entries(node.properties || {})
        .filter(([key]) => !hiddenKeys.includes(key))
        .sort(([a], [b]) => {
          const bottomKeys = ['created_at', 'updated_at']
          const aIsBottom = bottomKeys.includes(a)
          const bIsBottom = bottomKeys.includes(b)
          if (aIsBottom && !bIsBottom) return 1
          if (!aIsBottom && bIsBottom) return -1
          if (aIsBottom && bIsBottom) return bottomKeys.indexOf(a) - bottomKeys.indexOf(b)
          return 0
        })
    : []

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      position="left"
      mode="push"
      title={node ? `${node.type}: ${node.name}` : undefined}
    >
      {node && (
        <>
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <h3 className={styles.sectionTitleBasicInfo}>Basic Info</h3>
              {node.type === 'Exploit' && onDeleteNode && (
                <button
                  className={styles.deleteButton}
                  onClick={handleDelete}
                  disabled={isDeleting}
                  title="Delete exploit node"
                >
                  {isDeleting ? '...' : '\uD83D\uDDD1'}
                </button>
              )}
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>Type</span>
              <span
                className={styles.propertyBadge}
                style={{ backgroundColor: getNodeColor(node) }}
              >
                {node.type}
              </span>
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>ID</span>
              <span className={styles.propertyValue}>{node.id}</span>
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>Name</span>
              <span className={styles.propertyValue}>{node.name}</span>
            </div>
          </div>

          <div className={styles.section}>
            <h3 className={styles.sectionTitleProperties}>Properties</h3>
            {sortedProperties.map(([key, value]) => (
              <div key={key} className={styles.propertyRow}>
                <span className={styles.propertyKey}>{key}</span>
                <span className={styles.propertyValue}>
                  {formatPropertyValue(value)}
                </span>
              </div>
            ))}
            {sortedProperties.length === 0 && (
              <p className={styles.emptyProperties}>No additional properties</p>
            )}
          </div>
        </>
      )}
    </Drawer>
  )
}
