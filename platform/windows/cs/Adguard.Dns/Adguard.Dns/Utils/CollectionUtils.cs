using System;
using System.Collections.Generic;
using System.Linq;

namespace Adguard.Dns.Utils
{
    /// <summary>
    /// Helpers for working with collections
    /// </summary>
    internal class CollectionUtils
    {
        /// <summary>Determines whether two sequences are equal by comparing their
        /// elements by using a specified <see cref="T:System.Collections.Generic.IEqualityComparer`1" />.</summary>
        /// <param name="first">An <see cref="T:System.Collections.Generic.IEnumerable`1" />
        /// to compare to the <paramref name="second" /> sequence.</param>
        /// <param name="second">An <see cref="T:System.Collections.Generic.IEnumerable`1" />
        /// to compare to the <paramref name="first" /> sequence.</param>
        /// <param name="comparer">An <see cref="T:System.Collections.Generic.IEqualityComparer`1" />
        /// to use to compare elements.</param>
        /// <typeparam name="TSource">The type of the elements of the input sequences.</typeparam>
        /// <returns>
        /// <see langword="true" /> if the two source sequences both are null or are of equal length
        /// and their corresponding elements compare equal according to <paramref name="comparer" />;
        /// otherwise, <see langword="false" />.</returns>
        internal static bool SequenceEqual<TSource>(
            ICollection<TSource> first,
            ICollection<TSource> second,
            IEqualityComparer<TSource> comparer = null)
        {
            try
            {
                if (first == null || second == null)
                {
                    return (first == null) == (second == null);
                }

                if (first.Count != second.Count)
                {
                    return false;
                }

                return Enumerable.SequenceEqual(first, second, comparer);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}