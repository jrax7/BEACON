export function progressWidthClass(
  value,
) {
  const numeric =
    Number(value)

  if (
    !Number.isFinite(
      numeric,
    )
  ) {
    return 'progress-width-0'
  }

  const normalized =
    Math.max(
      0,
      Math.min(
        100,
        Math.round(
          numeric,
        ),
      ),
    )

  return `progress-width-${normalized}`
}
