import styles from './MitreTag.module.css';

export function MitreTag({ id }: { id?: string | null }) {
  if (!id) return <span className={styles.dash}>—</span>;
  return (
    <a
      className={styles.tag}
      href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}`}
      target="_blank"
      rel="noopener noreferrer"
    >
      {id}
    </a>
  );
}
