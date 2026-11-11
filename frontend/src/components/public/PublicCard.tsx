import { Link } from 'react-router-dom';
import '../../styles/components/PublicCard.css';

interface PublicCardProps {
  to: string;
  name: string;
  description: string;
  imageUrl: string | null;
  heading: 'h2' | 'h3';
}

export function PublicCard({ to, name, description, imageUrl, heading: Heading }: PublicCardProps) {
  return (
    <Link className="public-card" to={to}>
      <div className="public-card__image-wrap" aria-hidden="true">
        {imageUrl ? <img className="public-card__image" src={imageUrl} alt="" loading="lazy" />
          : <span className="public-card__placeholder">◇</span>}
      </div>
      <div className="public-card__content">
        <Heading className="public-card__name">{name}</Heading>
        {description && <p className="public-card__description">{description}</p>}
      </div>
      <span className="public-card__arrow" aria-hidden="true">↗</span>
    </Link>
  );
}
