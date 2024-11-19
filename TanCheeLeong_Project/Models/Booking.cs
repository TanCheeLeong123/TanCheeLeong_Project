﻿using System.ComponentModel.DataAnnotations;

namespace TanCheeLeong_Project.Models
{
    public class Booking
    {
        [Key]

        public int BookingId { get; set; }

        public string? FacilityDescription { get; set; }

        public string? BookingDateFrom { get; set; }

        public string? BookingDateTo { get; set; }

        public string? BookedBy { get; set; }

        public string? BookingStatus { get; set; }
    }
}
