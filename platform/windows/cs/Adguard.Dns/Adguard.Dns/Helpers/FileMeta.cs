namespace Adguard.Dns.Helpers
{
    /// <summary>
    /// Represents file's meta data 
    /// </summary>
    internal class FileMeta
    {
        /// <summary>
        /// Process-related executable description
        /// </summary>
        internal string FileDescription { get; set; }
        
        /// <summary>
        /// Process-related executable name (including ".exe")
        /// </summary>
        internal string Executable { get; set; }
        
        /// <summary>
        /// Full path of the Process-related executable
        /// </summary>
        internal string FullPath { get; set; }
        
        /// <summary>
        /// Process-related product name
        /// </summary>
        internal string ProductName { get; set; }
        
        public override string ToString()
        {
            return string.Format("{0} ({1})", FileDescription, Executable);
        }
    }
}