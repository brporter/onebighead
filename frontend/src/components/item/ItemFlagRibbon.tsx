import { UserFlag } from '../../utils/types';

interface ItemFlagRibbonProps {
  userFlag: UserFlag;
}

/**
 * A corner ribbon that displays the item's user flag status.
 * Similar to the "Fork me on GitHub" ribbon style.
 * Only displays for Want and TradeOrSell flags (Have is shown differently).
 */
function ItemFlagRibbon({ userFlag }: ItemFlagRibbonProps) {
  // Only show ribbon for Want and TradeOrSell flags
  if (userFlag !== UserFlag.Want && userFlag !== UserFlag.TradeOrSell) {
    return null;
  }

  const isWant = userFlag === UserFlag.Want;
  const label = isWant ? 'I Want This!' : 'For Trade/Sale';
  const className = isWant
    ? 'itemFlagRibbon itemFlagRibbon--want'
    : 'itemFlagRibbon itemFlagRibbon--trade';

  return (
    <div className={className}>
      <span className="itemFlagRibbon__text">{label}</span>
    </div>
  );
}

export default ItemFlagRibbon;
